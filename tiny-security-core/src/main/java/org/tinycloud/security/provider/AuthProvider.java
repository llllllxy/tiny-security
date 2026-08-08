package org.tinycloud.security.provider;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextUtils;
import org.tinycloud.security.event.LoginFailureEvent;
import org.tinycloud.security.event.LoginSuccessEvent;
import org.tinycloud.security.event.NoopSecurityEventPublisher;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.CookieUtil;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.tinycloud.security.util.JwtUtil;
import org.tinycloud.security.web.WebRequestUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 操作 token 和会话的兼容外观类（Facade）
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class AuthProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthProvider.class);

    private final SessionRepository sessionRepository;
    private final AuthProperties properties;
    private final SecurityEventPublisher securityEventPublisher;

    /**
     * 构造 AuthProvider 外观。
     *
     * @param sessionRepository       会话仓储
     * @param properties              配置属性
     * @param securityEventPublisher  安全事件发布器
     */
    public AuthProvider(SessionRepository sessionRepository,
                        AuthProperties properties,
                        SecurityEventPublisher securityEventPublisher) {
        Assert.notNull(sessionRepository, "SessionRepository cannot be null!");
        Assert.notNull(properties, "AuthProperties cannot be null!");
        this.sessionRepository = sessionRepository;
        this.properties = properties;
        this.securityEventPublisher = securityEventPublisher;
    }

    /**
     * 从指定请求中提取并解析 token（去除 Bearer 前缀）。
     *
     * @param request HTTP 请求
     * @return 去前缀后的 token
     */
    public String getToken(HttpServletRequest request) {
        String jwtToken = WebRequestUtils.getToken(request, properties.getTokenName());
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            return jwtToken.substring(AuthConsts.JWT_TOKEN_PREFIX.length());
        }
        throw new UnAuthorizedException();
    }

    /**
     * 从当前请求上下文提取并解析 token（去除 Bearer 前缀）。
     *
     * @return 去前缀后的 token
     */
    public String getToken() {
        String jwtToken = WebRequestUtils.getToken(properties.getTokenName());
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            return jwtToken.substring(AuthConsts.JWT_TOKEN_PREFIX.length());
        }
        throw new UnAuthorizedException();
    }

    /**
     * 根据 token 解析会话凭证 credentials。
     *
     * @param token token 字符串（可包含 Bearer 前缀）
     * @return 会话凭证
     */
    public String getCredentialsByToken(String token) {
        if (!StringUtils.hasText(token)) {
            throw new UnAuthorizedException();
        }
        if (token.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            token = token.substring(AuthConsts.JWT_TOKEN_PREFIX.length());
        }
        Map<String, String> claims = JwtUtil.getClaims(properties.getJwtSecret(), token);
        if (Objects.isNull(claims)) {
            throw new UnAuthorizedException();
        }
        return claims.get("credentials");
    }

    /**
     * 从当前请求上下文获取会话凭证。
     *
     * @return 会话凭证
     */
    public String getCredentials() {
        return getCredentialsByToken(getToken());
    }

    /**
     * 从指定请求中获取会话凭证。
     *
     * @param request HTTP 请求
     * @return 会话凭证
     */
    public String getCredentials(HttpServletRequest request) {
        return getCredentialsByToken(getToken(request));
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

        String credentials = CredentialsGenUtil.generate(properties.getCredentialsStyle());
        Map<String, String> payload = new HashMap<>();
        payload.put("credentials", credentials);
        String jwtToken = JwtUtil.sign(properties.getJwtSecret(), properties.getJwtSubject(), payload);

        long currentTime = System.currentTimeMillis();
        int timeout = resolveTimeout();
        LoginSubject subject = new LoginSubject();
        subject.setCredentials(credentials);
        subject.setExtraInfo(extraInfo);
        subject.setLoginId(loginId);
        subject.setLoginTime(currentTime);
        subject.setLoginExpireTime(currentTime + timeout * 1000L);

        boolean success = sessionRepository.save(subject, timeout, resolveMaxConcurrentLogins());
        if (!success) {
            throw new TinySecurityException("Failed to create auth. Please retry!");
        }
        return AuthConsts.JWT_TOKEN_PREFIX + jwtToken;
    }

    /**
     * 刷新指定凭证对应会话。
     *
     * @param credentials 会话凭证
     * @param subject     登录主体
     * @return 是否刷新成功
     */
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        return sessionRepository.refreshByCredentials(credentials, subject, resolveTimeout());
    }

    /**
     * 校验指定凭证是否仍然有效。
     *
     * @param credentials 会话凭证
     * @return true-有效，false-无效
     */
    public boolean checkByCredentials(String credentials) {
        return sessionRepository.checkByCredentials(credentials);
    }

    /**
     * 根据凭证获取登录主体。
     *
     * @param credentials 会话凭证
     * @return 登录主体
     */
    public LoginSubject getSubject(String credentials) {
        return sessionRepository.getSubject(credentials);
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
        return sessionRepository.deleteByCredentials(credentials);
    }

    /**
     * 删除指定账号下所有会话。
     *
     * @param loginId 账号ID
     * @return 是否删除成功
     */
    public boolean deleteByLoginId(Object loginId) {
        return sessionRepository.deleteByLoginId(loginId);
    }

    /**
     * 登录（不带扩展信息）。
     *
     * @param loginId 登录账号ID
     * @return 带前缀 token
     */
    public String login(Object loginId) {
        return login(loginId, null);
    }

    /**
     * 登录并发布成功/失败事件。
     *
     * @param loginId   登录账号ID
     * @param extraInfo 扩展信息
     * @return 带前缀的 token
     */
    public String login(Object loginId, Map<String, Object> extraInfo) {
        try {
            String token = this.createAuth(loginId, extraInfo);
            CookieUtil.setCookie(WebRequestUtils.getResponse(), properties.getTokenName(), token);
            resolveSecurityEventPublisher().publishLoginSuccess(new LoginSuccessEvent(loginId, token, extraInfo, System.currentTimeMillis()));
            return token;
        } catch (RuntimeException ex) {
            resolveSecurityEventPublisher().publishLoginFailure(new LoginFailureEvent(
                    loginId,
                    extraInfo,
                    ex.getMessage(),
                    System.currentTimeMillis()
            ));
            throw ex;
        }
    }

    /**
     * 基于当前请求上下文登出。
     */
    public void logout() {
        this.deleteByCredentials(this.getCredentials());
    }

    /**
     * 基于指定请求登出。
     *
     * @param request HTTP 请求
     */
    public void logout(HttpServletRequest request) {
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
        return String.valueOf(getLoginId());
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID
     */
    public Integer getLoginIdAsInt() {
        return Integer.parseInt(String.valueOf(getLoginId()));
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID
     */
    public Long getLoginIdAsLong() {
        return Long.parseLong(String.valueOf(getLoginId()));
    }

    /**
     * 获取当前请求安全上下文。
     *
     * @return 安全上下文
     */
    public SecurityContext getSecurityContext() {
        // 优先复用拦截器阶段已建立的上下文，避免重复构建
        SecurityContext context = SecurityContextUtils.getSecurityContext();
        if (context != null && context.getLoginSubject() != null) {
            return context;
        }
        throw new UnAuthorizedException();
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
            log.error("AuthProvider isLogin failed, Exception：{e}", e);
            return false;
        }
    }

    /**
     * 校验当前请求是否已登录，未登录则抛异常。
     *
     * @return true-已登录
     */
    public boolean checkLogin() {
        boolean success = this.checkByCredentials(this.getCredentials());
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
        Integer timeout = properties.getTimeout();
        return timeout == null ? 1800 : timeout;
    }

    /**
     * 解析最大并发登录数。
     *
     * @return 最大并发登录数，默认0（不限制）
     */
    private int resolveMaxConcurrentLogins() {
        Integer maxConcurrentLogins = properties.getMaxConcurrentLogins();
        return maxConcurrentLogins == null ? 0 : maxConcurrentLogins;
    }

    /**
     * 解析安全事件发布器，缺省返回空实现。
     *
     * @return 安全事件发布器
     */
    private SecurityEventPublisher resolveSecurityEventPublisher() {
        if (securityEventPublisher == null) {
            return new NoopSecurityEventPublisher();
        }
        return securityEventPublisher;
    }
}
