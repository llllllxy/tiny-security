package org.tinycloud.security.provider;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.enums.CookieSameSite;
import org.tinycloud.security.event.LoginFailureEvent;
import org.tinycloud.security.event.LoginSuccessEvent;
import org.tinycloud.security.event.NoopSecurityEventPublisher;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.CommonUtil;
import org.tinycloud.security.util.CookieUtil;
import org.tinycloud.security.util.TokenSignUtil;
import org.tinycloud.security.web.WebRequestUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * 操作 token 和会话的兼容外观类（Facade）
 *
 * <p><b>1.5.0 起本类是框架唯一的实例门面</b>：既负责 token 与会话读写，也负责当前请求的
 * 上下文与授权判定 —— 后者继承自内部基类 {@code TinySecurityFacade}，因此
 * {@code getLoginId() / getRoleSet() / hasRole()} 等方法在本类上直接可用，
 * 且不再需要任何静态全局变量来定位实现（P1-1 / P1-2）。
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class AuthProvider extends TinySecurityFacade {
    private static final Logger log = LoggerFactory.getLogger(AuthProvider.class);

    /**
     * 会话仓储：token 只是凭证的签名信封，真正的登录主体与有效期存在这里
     * （对应 tiny-security.store-type 的 single / caffeine / redis / jdbc 四种实现）
     */
    private final SessionRepository sessionRepository;

    /**
     * 框架配置（tiny-security.*）：token 名、会话有效期、Cookie 策略、并发登录上限等
     */
    private final AuthProperties properties;

    /**
     * 安全事件发布器：登录成功/失败等事件的出口；为 null 时降级为空实现，即只记日志不发布事件
     */
    private final SecurityEventPublisher securityEventPublisher;

    /**
     * 实际生效的 token 签名密钥：优先取配置值；未配置时生成随机密钥
     * （重启后所有会话失效，多实例部署下各实例互不认可）
     */
    private final String tokenSecret;

    /**
     * 构造 AuthProvider 外观（不含授权数据源，使用默认的 ThreadLocal 上下文仓储）。
     *
     * <p>该重载保持 1.5.0 之前的行为不变，适用于手工 {@code new} 的场景；此时
     * {@code getRoleSet() / getPermissionSet()} 只读取上下文中已有的数据，不做按需懒加载。
     *
     * @param sessionRepository       会话仓储
     * @param properties              配置属性
     * @param securityEventPublisher  安全事件发布器
     */
    public AuthProvider(SessionRepository sessionRepository,
                        AuthProperties properties,
                        SecurityEventPublisher securityEventPublisher) {
        this(sessionRepository, properties, securityEventPublisher,
                new ThreadLocalSecurityContextRepository(), null);
    }

    /**
     * 构造 AuthProvider 外观（完整形态）。
     *
     * <p>这里必须把 {@link AuthorizationInfoGet} 一并注入：接口上没有权限注解时授权管理器不会主动查
     * 角色/权限（性能设计），此时 {@code hasRole/hasPermission} 依赖按需懒加载（P0-1）。
     *
     * @param sessionRepository         会话仓储
     * @param properties                配置属性
     * @param securityEventPublisher    安全事件发布器
     * @param securityContextRepository 安全上下文仓储
     * @param authorizationInfoGet      角色权限数据提供者，可为 null
     */
    public AuthProvider(SessionRepository sessionRepository,
                        AuthProperties properties,
                        SecurityEventPublisher securityEventPublisher,
                        SecurityContextRepository securityContextRepository,
                        AuthorizationInfoGet authorizationInfoGet) {
        super(securityContextRepository, authorizationInfoGet);
        Assert.notNull(sessionRepository, "SessionRepository cannot be null!");
        Assert.notNull(properties, "The properties cannot be null!");
        this.sessionRepository = sessionRepository;
        this.properties = properties;
        this.securityEventPublisher = securityEventPublisher;
        this.tokenSecret = resolveTokenSecret(properties.getTokenSecret());
        Integer timeout = properties.getTimeout();
        Assert.isTrue(timeout == null || timeout > 0,
                "Invalid tiny-security.timeout: " + timeout + ". It must be a positive number of seconds.");
        // 弱密钥告警（不阻止启动，避免破坏存量部署）
        warnIfTokenSecretTooShort(properties.getTokenSecret());
        // SameSite=None 必须配合 Secure，否则浏览器会直接丢弃 Cookie
        warnIfCookieSameSiteNoneWithoutSecure();
    }

    /**
     * token 签名密钥长度告警。
     *
     * <p>HMAC-SHA256 的密钥短于摘要长度（32 字节）会削弱抗暴力破解强度。这里**只告警不报错** ——
     * 强制最小长度会让存量配置（如 {@code token-secret: 123}）升级后直接启动失败，属破坏性变更。
     * 未配置时走随机密钥路径（{@link #resolveTokenSecret()}），随机串为 128 位，不受本告警影响。
     */
    private void warnIfTokenSecretTooShort(String configuredSecret) {
        if (!StringUtils.hasText(configuredSecret)) {
            return;
        }
        int length = configuredSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (length < 32) {
            log.warn("tiny-security: tiny-security.token-secret is too short ({} bytes, recommended >= 32 bytes). "
                            + "A short key weakens HMAC-SHA256 resistance to brute force. "
                            + "Please use a long random secret, e.g. openssl rand -base64 48.",
                    length);
        }
    }

    /**
     * 检测 {@code cookie-same-site: NONE} 与 {@code cookie-secure: false} 的非法组合。
     *
     * <p>{@code SameSite=None} 的 Cookie 规范要求必须伴随 {@code Secure}，否则浏览器会**直接丢弃**
     * 该 Cookie —— 表现为「登录成功但下一个请求又是未登录」。这里只告警，不擅自改写用户的
     * 配置值（框架替用户猜配置会引入歧义）。
     */
    private void warnIfCookieSameSiteNoneWithoutSecure() {
        if (this.resolveEnableCookie()
                && this.properties.getCookieSameSite() == CookieSameSite.NONE
                && !this.resolveCookieSecure()) {
            log.warn("tiny-security: tiny-security.cookie-same-site is NONE but tiny-security.cookie-secure is false. "
                    + "Browsers reject SameSite=None cookies without the Secure attribute, so the login cookie will be dropped. "
                    + "Please set tiny-security.cookie-secure=true (requires HTTPS), or use cookie-same-site=LAX.");
        }
    }

    /**
     * 从指定请求中提取 token（**带 {@code Bearer } 前缀**）。
     *
     * <p>返回值与 {@link #login()} 的返回值形态一致，可直接放回 {@code Authorization} 头使用。
     * 需要不带前缀的裸值请用 {@link #getRawToken(HttpServletRequest)}。
     *
     * @param request HTTP 请求
     * @return 带前缀的 token
     */
    public String getToken(HttpServletRequest request) {
        String token = WebRequestUtils.getToken(request, this.properties.getTokenName(), resolveEnableCookie(), resolveEnableUrlToken());
        if (!StringUtils.hasText(token) || !token.startsWith(AuthConsts.TOKEN_PREFIX)) {
            throw new UnAuthorizedException();
        }
        return token;
    }

    /**
     * 从当前请求上下文提取 token（**带 {@code Bearer } 前缀**）。
     *
     * <p>返回值与 {@link #login()} 的返回值形态一致，可直接放回 {@code Authorization} 头使用。
     * 需要不带前缀的裸值请用 {@link #getRawToken()}。
     *
     * @return 带前缀的 token
     */
    public String getToken() {
        String token = WebRequestUtils.getToken(this.properties.getTokenName(), resolveEnableCookie(), resolveEnableUrlToken());
        if (!StringUtils.hasText(token) || !token.startsWith(AuthConsts.TOKEN_PREFIX)) {
            throw new UnAuthorizedException();
        }
        return token;
    }

    /**
     * 从指定请求中提取 token 并**去掉 {@code Bearer } 前缀**（裸凭证信封）。
     *
     * <p>内部鉴权链路使用该方法；对外请优先用 {@link #getToken(HttpServletRequest)}。
     *
     * @param request HTTP 请求
     * @return 去前缀后的 token
     */
    public String getRawToken(HttpServletRequest request) {
        return this.getToken(request).substring(AuthConsts.TOKEN_PREFIX.length());
    }

    /**
     * 从当前请求上下文提取 token 并**去掉 {@code Bearer } 前缀**（裸凭证信封）。
     *
     * <p>内部鉴权链路使用该方法；对外请优先用 {@link #getToken()}。
     *
     * @return 去前缀后的 token
     */
    public String getRawToken() {
        return this.getToken().substring(AuthConsts.TOKEN_PREFIX.length());
    }

    /**
     * 根据 token 解析会话凭证 credentials。
     *
     * <p>先用签名密钥校验 token 完整性（防伪造），通过后再取出其中的 credentials；
     * credentials 是否对应一个有效会话，由会话仓储在后续 {@code checkByCredentials} 中判定。
     *
     * @param token token 字符串（可包含 Bearer 前缀）
     * @return 会话凭证
     */
    public String getCredentialsByToken(String token) {
        if (!StringUtils.hasText(token)) {
            throw new UnAuthorizedException();
        }
        if (token.startsWith(AuthConsts.TOKEN_PREFIX)) {
            token = token.substring(AuthConsts.TOKEN_PREFIX.length());
        }
        String credentials = TokenSignUtil.verifyAndExtract(this.tokenSecret, token);
        if (Objects.isNull(credentials)) {
            throw new UnAuthorizedException();
        }
        return credentials;
    }

    /**
     * 从当前请求上下文获取会话凭证。
     *
     * @return 会话凭证
     */
    public String getCredentials() {
        return this.getCredentialsByToken(this.getToken());
    }

    /**
     * 从指定请求中获取会话凭证。
     *
     * @param request HTTP 请求
     * @return 会话凭证
     */
    public String getCredentials(HttpServletRequest request) {
        return this.getCredentialsByToken(this.getToken(request));
    }

    /**
     * 创建会话并返回 token（不写 cookie）。
     *
     * @param loginId   登录账号ID
     * @param extraInfo 扩展信息
     * @return 带前缀 token
     */
    private String createAuth(Object loginId, Map<String, Object> extraInfo) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        Assert.isTrue(loginId instanceof Number || loginId instanceof String,
                "loginId must be of type Number (Long, Integer, etc.) or String, but got: " + loginId.getClass().getName());

        // 凭证是会话的唯一钥匙，必须不可预测：固定用 UUID（内部走 SecureRandom，122 bit 随机性）再去掉横线。
        // 不再提供 credentials-style 配置项——可选的凭证风格只会带来"用户选到弱随机源"的风险，没有收益
        String credentials = UUID.randomUUID().toString().replace("-", "");

        long currentTime = System.currentTimeMillis();
        int timeout = this.resolveTimeout();
        LoginSubject subject = new LoginSubject();
        subject.setCredentials(credentials);
        subject.setExtraInfo(extraInfo);
        subject.setLoginId(loginId);
        subject.setLoginTime(currentTime);
        subject.setLoginExpireTime(currentTime + timeout * 1000L);

        boolean success = this.sessionRepository.save(subject, timeout, this.resolveMaxConcurrentLogins());
        if (!success) {
            throw new TinySecurityException("Failed to create auth. Please retry!");
        }
        return AuthConsts.TOKEN_PREFIX + TokenSignUtil.sign(this.tokenSecret, credentials);
    }

    /**
     * 刷新指定凭证对应会话。
     *
     * <p><b>过期口径必须与存储层 TTL 一致</b>：本方法在延长存储层 TTL 的同时，会把
     * {@code subject.loginExpireTime} 一并推进到 {@code now + timeout}。
     * 内核的「绝对过期校验」判定的正是这个时间戳，若只延长 TTL 而不推进它，
     * 就会出现「存储里还有会话、用户却已经 401」的分叉（P1-14）——
     * 表现为续期看起来没生效。此处与 {@code DefaultAuthenticationManager}
     * 自己的滑动续期路径（先 set 再 refresh）保持同一口径。
     *
     * <p>注意本方法会**改写传入的 subject**（写入新的过期时间戳）。
     *
     * @param credentials 会话凭证
     * @param subject     登录主体（可为 null，此时退化为纯 TTL 延长）
     * @return 是否刷新成功
     */
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        int timeout = resolveTimeout();
        // 先推进时间戳再落库：四种仓储都会把 subject 存下（内存版存引用、redis/jdbc 序列化），
        // 因此这一步同时修正「存储层 TTL」与「绝对过期时间戳」两套口径。
        if (subject != null) {
            subject.setLoginExpireTime(System.currentTimeMillis() + timeout * 1000L);
        }
        return this.sessionRepository.refreshByCredentials(credentials, subject, timeout);
    }

    /**
     * 校验指定凭证是否仍然有效。
     *
     * @param credentials 会话凭证
     * @return true-有效，false-无效
     */
    public boolean checkByCredentials(String credentials) {
        return this.sessionRepository.checkByCredentials(credentials);
    }

    /**
     * 根据凭证获取登录主体。
     *
     * @param credentials 会话凭证
     * @return 登录主体
     */
    public LoginSubject getSubject(String credentials) {
        return this.sessionRepository.getSubject(credentials);
    }

    /**
     * 根据 token 删除会话。
     *
     * @param token token 字符串
     * @return 是否删除成功
     */
    public boolean deleteByToken(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String credentials = this.getCredentialsByToken(token);
            return this.deleteByCredentials(credentials);
        } catch (Exception e) {
            log.error("AuthProvider deleteByToken failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证删除会话。
     *
     * @param credentials 会话凭证
     * @return 是否删除成功
     */
    public boolean deleteByCredentials(String credentials) {
        return this.sessionRepository.deleteByCredentials(credentials);
    }

    /**
     * 删除指定账号下所有会话。
     *
     * @param loginId 账号ID
     * @return 是否删除成功
     */
    public boolean deleteByLoginId(Object loginId) {
        return this.sessionRepository.deleteByLoginId(loginId);
    }

    /**
     * 获取指定账号下全部有效（未过期）会话凭证。
     *
     * <p>典型用途：多设备管理（列出账号的所有在线设备/会话）、定向下线
     * （配合 {@link #deleteByCredentials(String)} 只踢掉某个凭证，
     * 而非 {@link #deleteByLoginId(Object)} 的全量踢出）。
     *
     * <p>注意：凭证即会话钥匙，等同于用户身份凭据，请勿输出到日志或返回给前端；
     * 且该方法依赖仓储的"账号 → 凭证"反向索引，内置四种仓储均已实现，
     * 自定义仓储未实现时抛 {@link UnsupportedOperationException}。
     *
     * @param loginId 账号ID
     * @return 有效会话凭证列表，无有效会话时返回空列表
     * @throws UnsupportedOperationException 当前会话仓储不支持按账号反查凭证时抛出
     */
    public List<String> getCredentialsByLoginId(Object loginId) {
        return this.sessionRepository.getCredentialsByLoginId(loginId);
    }

    /**
     * 登录（不带扩展信息）。
     *
     * @param loginId 登录账号ID
     * @return 带前缀 token
     */
    public String login(Object loginId) {
        return this.login(loginId, null);
    }

    /**
     * 登录并发布成功/失败事件。
     *
     * @param loginId   登录账号ID
     * @param extraInfo 扩展信息
     * @return 带前缀的 token
     */
    public String login(Object loginId, Map<String, Object> extraInfo) {
        String token;
        try {
            token = this.createAuth(loginId, extraInfo);
            if (resolveEnableCookie()) {
                // cookie 生存期与会话 timeout 保持一致，并带上 Secure/SameSite 安全属性
                CookieUtil.setCookie(WebRequestUtils.getResponse(), this.properties.getTokenName(), token,
                        "/", this.resolveTimeout(), this.resolveCookieSecure(), this.resolveCookieSameSite());
            }
        } catch (RuntimeException ex) {
            // 失败事件的发布必须与原始异常隔离：监听器自身抛异常时，
            // 若放任其传播会顶掉这里的原始异常，调用方与异常翻译器
            // 将看不到真实的登录失败原因（与下方成功路径的处理保持一致）。
            try {
                this.resolveSecurityEventPublisher().publishLoginFailure(new LoginFailureEvent(
                        loginId,
                        extraInfo,
                        ex.getMessage(),
                        System.currentTimeMillis()
                ));
            } catch (Exception publishEx) {
                log.warn("AuthProvider publishLoginFailure failed, Exception：", publishEx);
            }
            throw ex;
        }
        // 成功事件发布移出 try 块：会话已创建成功，监听器抛异常不应被误判为登录失败，
        // 也不应影响登录结果（仅记录 WARN）。
        try {
            this.resolveSecurityEventPublisher().publishLoginSuccess(new LoginSuccessEvent(loginId, token, extraInfo, System.currentTimeMillis()));
        } catch (Exception ex) {
            log.warn("AuthProvider publishLoginSuccess failed, Exception：", ex);
        }
        return token;
    }

    /**
     * 基于当前请求上下文登出。
     */
    public void logout() {
        if (resolveEnableCookie()) {
            // 删除指令必须带上与写入时一致的安全属性：SameSite=None 的 Cookie 若删除时不带
            // SameSite+Secure，浏览器会忽略该删除指令，表现为"登出后仍是登录态"（P1-5）
            CookieUtil.removeCookie(WebRequestUtils.getResponse(), this.properties.getTokenName(),
                    "/", this.resolveCookieSecure(), this.resolveCookieSameSite());
        }
        this.deleteByCredentials(this.getCredentials());
    }

    /**
     * 基于指定请求登出。
     *
     * @param request HTTP 请求
     */
    public void logout(HttpServletRequest request) {
        if (resolveEnableCookie()) {
            CookieUtil.removeCookie(WebRequestUtils.getResponse(request), this.properties.getTokenName(),
                    "/", this.resolveCookieSecure(), this.resolveCookieSameSite());
        }
        this.deleteByCredentials(this.getCredentials(request));
    }

    /**
     * 从安全上下文获取当前登录用户。
     *
     * @return 登录账号ID
     */
    public LoginSubject getLoginSubject() {
        return this.getSecurityContext().getLoginSubject();
    }

    /**
     * 从安全上下文获取当前登录账号ID。
     *
     * @return 登录账号ID
     */
    public Object getLoginId() {
        return this.getLoginSubject().getLoginId();
    }

    /**
     * 获取当前登录账号ID（字符串形式）。
     *
     * @return 字符串账号ID
     */
    public String getLoginIdAsString() {
        return String.valueOf(this.getLoginId());
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID
     * @throws UnAuthorizedException 未登录时
     * @throws TinySecurityException loginId 非数字时
     */
    public Integer getLoginIdAsInt() {
        Object loginId = this.getLoginId();
        try {
            return Integer.parseInt(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Integer: " + loginId);
        }
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID
     * @throws UnAuthorizedException 未登录时
     * @throws TinySecurityException loginId 非数字时
     */
    public Long getLoginIdAsLong() {
        Object loginId = this.getLoginId();
        try {
            return Long.parseLong(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Long: " + loginId);
        }
    }

    /**
     * 判断当前请求是否处于登录状态。
     *
     * @return true-已登录，false-未登录
     */
    public boolean isLogin() {
        try {
            return this.checkByCredentials(this.getCredentials());
        } catch (Exception e) {
            // 匿名请求也会走到这里（无 token），属正常流程，降为 debug 避免刷屏
            log.debug("AuthProvider isLogin failed, Exception：", e);
            return false;
        }
    }

    /**
     * 校验当前请求是否已登录，未登录则抛异常。
     *
     * <p>与 {@link #isLogin()} 的区别只在失败时「抛异常」还是「返回 false」，
     * 两者对**异常输入**的容错必须一致：token 缺失、验签失败、以及凭证为空白字符等情况
     * 都应归结为「未登录 → 401」，而不是把仓储参数的非法断言（{@code IllegalArgumentException}）
     * 透出去变成 HTTP 500。后者既误导调用方（以为是服务端错误），也污染错误监控。
     *
     * @return true-已登录
     */
    public boolean checkLogin() {
        boolean success;
        try {
            success = this.checkByCredentials(this.getCredentials());
        } catch (UnAuthorizedException e) {
            // token 缺失 / 未带前缀 / 验签失败 / 凭证为空白：语义上就是「未登录」，直接抛 401
            throw e;
        } catch (Exception e) {
            // 其余异常（如凭证为空导致仓储断言失败）同样按「未登录」处理，
            // 避免把 IllegalArgumentException 透成 500（P1-12）
            log.debug("AuthProvider checkLogin failed, Exception：", e);
            success = false;
        }
        if (!success) {
            throw new UnAuthorizedException();
        }
        return true;
    }

    /**
     * 解析会话超时时间（秒）。
     *
     * @return 超时时间，默认1800秒
     */
    private int resolveTimeout() {
        Integer timeout = this.properties.getTimeout();
        return timeout == null ? 1800 : timeout;
    }

    /**
     * 解析最大并发登录数。
     *
     * @return 最大并发登录数，默认0（不限制）
     */
    private int resolveMaxConcurrentLogins() {
        Integer maxConcurrentLogins = this.properties.getMaxConcurrentLogins();
        return maxConcurrentLogins == null ? 0 : maxConcurrentLogins;
    }

    /**
     * 解析 token 签名密钥：已配置则使用配置值；未配置则生成随机密钥并给出警告
     * （随机密钥重启后会变化，导致历史会话全部失效，且多实例之间互不认可，生产环境必须配置固定密钥）。
     *
     * @param configuredSecret 配置的密钥
     * @return 实际生效的密钥
     */
    private String resolveTokenSecret(String configuredSecret) {
        if (StringUtils.hasText(configuredSecret)) {
            return configuredSecret;
        }
        log.warn("tiny-security: tiny-security.token-secret is not configured, a temporary random secret has been generated. " +
                "All sessions will be invalid after restart, and in a multi-instance deployment each instance will reject tokens issued by the others! " +
                "Please configure a fixed secret for production environments.");
        return CommonUtil.getRandomString(128);
    }

    /**
     * 解析是否启用 Cookie 模式。
     *
     * @return 是否启用，默认 false（纯 token 模式）
     */
    private boolean resolveEnableCookie() {
        Boolean enableCookie = this.properties.getEnableCookie();
        return enableCookie != null && enableCookie;
    }

    /**
     * 解析是否允许从 URL 参数读取 token。
     *
     * @return 是否允许，默认 false（URL 传 token 存在访问日志/Referer 泄露风险，非必要不建议开启）
     */
    private boolean resolveEnableUrlToken() {
        Boolean enableUrlToken = this.properties.getEnableUrlToken();
        return enableUrlToken != null && enableUrlToken;
    }

    /**
     * 解析 Cookie Secure 属性。
     *
     * @return 是否仅 HTTPS 传输，默认 false
     */
    private boolean resolveCookieSecure() {
        Boolean cookieSecure = this.properties.getCookieSecure();
        return cookieSecure != null && cookieSecure;
    }

    /**
     * 解析 Cookie SameSite 属性。
     *
     * @return SameSite 属性值，默认 Lax
     */
    private String resolveCookieSameSite() {
        CookieSameSite cookieSameSite = this.properties.getCookieSameSite();
        return cookieSameSite == null ? CookieSameSite.LAX.getValue() : cookieSameSite.getValue();
    }

    /**
     * 解析安全事件发布器，缺省返回空实现。
     *
     * @return 安全事件发布器
     */
    private SecurityEventPublisher resolveSecurityEventPublisher() {
        if (this.securityEventPublisher == null) {
            return new NoopSecurityEventPublisher();
        }
        return this.securityEventPublisher;
    }
}
