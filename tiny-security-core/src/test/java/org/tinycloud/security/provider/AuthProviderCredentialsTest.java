package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthProvider#getCredentialsByLoginId 门面方法测试。
 *
 * <p>核心回归点：① 门面正确透传仓储结果（多会话/无会话两种场景）；
 * ② 自定义仓储未重写该方法时抛 {@link UnsupportedOperationException}
 * （接口用 default 方法保持编译兼容，但行为必须显式报错而非静默返回空列表）。</p>
 */
class AuthProviderCredentialsTest {

    private SingleSessionRepository repository;
    private AuthProvider authProvider;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        repository = new SingleSessionRepository();
        authProvider = new AuthProvider(repository, properties(), null);
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * 同一账号多次登录后，门面应返回全部有效凭证。
     */
    @Test
    void shouldReturnAllCredentialsOfLoginId() {
        authProvider.login(10001L, null);
        authProvider.login(10001L, null);

        List<String> credentials = authProvider.getCredentialsByLoginId(10001L);

        assertEquals(2, credentials.size());
    }

    /**
     * 账号无有效会话时返回空列表（不返回 null）。
     */
    @Test
    void shouldReturnEmptyListWhenNoSession() {
        List<String> credentials = authProvider.getCredentialsByLoginId(99999L);

        assertEquals(0, credentials.size());
    }

    /**
     * 登出后该凭证不再出现在查询结果中（门面 logout → 仓储删除 → 查询收敛）。
     */
    @Test
    void shouldExcludeLoggedOutCredential() {
        String firstToken = authProvider.login(10002L, null);
        authProvider.login(10002L, null);
        assertEquals(2, authProvider.getCredentialsByLoginId(10002L).size());

        // logout 从当前请求读取 token（login 返回值已带 Bearer 前缀）
        request.addHeader("token", firstToken);
        authProvider.logout();

        assertEquals(1, authProvider.getCredentialsByLoginId(10002L).size());
    }

    /**
     * 自定义仓储未实现该方法时必须显式报错，而不是静默返回空列表。
     */
    @Test
    void shouldThrowWhenRepositoryDoesNotSupportLookup() {
        AuthProvider providerWithCustomRepo = new AuthProvider(new NoLookupSessionRepository(), properties(), null);

        assertThrows(UnsupportedOperationException.class,
                () -> providerWithCustomRepo.getCredentialsByLoginId(10003L));
    }

    /**
     * 凭证为**空白字符**的 token 必须得到 401（P1-12），不得抛 {@link IllegalArgumentException}（→ 500）。
     *
     * <p>可达性（已实测确认，非推测）：token 形态是 {@code credentials.signature}，凭证即分隔符
     * 左侧内容。{@code TokenSignUtil.sign} 用 {@code Assert.hasText} 拦住空凭证，但**用同一 secret
     * 自行计算 HMAC 即可绕过**（同密钥的其他用途、或密钥泄露场景）。实测
     * {@code " " + "." + base64url(HMAC-SHA256(" ", secret))} 这种 token 会被
     * {@code verifyAndExtract} 原样返回为 {@code " "}。
     *
     * <p>此时 {@code checkLogin()} 把 {@code " "} 交给会话仓储，命中内置仓储里
     * {@code Assert.hasText(credentials, ...)} 抛出的 {@code IllegalArgumentException}；它不是
     * {@link org.tinycloud.security.exception.TinySecurityException}，异常解析器返回 null，
     * 最终交给 Spring 默认处理 → **HTTP 500**，而非应有的 401。
     *
     * <p>对照 {@link AuthProvider#isLogin()}：那里已 catch {@code Exception} 返回 false，是正确写法。
     */
    @Test
    void shouldRejectBlankCredentialsTokenWithUnauthorizedInsteadOf500() {
        request.addHeader("token", AuthConsts.TOKEN_PREFIX
                + signedToken("test-token-secret-for-credentials-lookup", " "));

        assertThrows(UnAuthorizedException.class,
                () -> authProvider.checkLogin(),
                "空白凭证必须按未登录处理（401），不能抛 IllegalArgumentException 导致 500");
    }

    /**
     * 同一缺陷的第二种表现：{@code isLogin()} 与 {@code checkLogin()} 对空白凭证的行为必须一致
     * （前者返回 false，后者抛 401），不能一个容错、一个 500。
     */
    @Test
    void blankCredentialsShouldBehaveConsistentlyBetweenIsLoginAndCheckLogin() {
        request.addHeader("token", AuthConsts.TOKEN_PREFIX
                + signedToken("test-token-secret-for-credentials-lookup", " "));

        assertFalse(authProvider.isLogin(), "isLogin 对空白凭证应返回 false");
        assertThrows(UnAuthorizedException.class, () -> authProvider.checkLogin());
    }

    /**
     * 构造「凭证.签名」形态的 token：用于生成 {@code sign()} 拒绝产出的畸形 token（空白凭证）。
     */
    private static String signedToken(String secret, String credentials) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(credentials.getBytes(StandardCharsets.UTF_8)));
            return credentials + "." + signature;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setTokenSecret("test-token-secret-for-credentials-lookup");
        return properties;
    }

    /**
     * 未实现 getCredentialsByLoginId 的自定义仓储（模拟升级前的存量实现）。
     */
    static class NoLookupSessionRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return false;
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            return null;
        }

        @Override
        public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
            return true;
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            return true;
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            return true;
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            return 0;
        }
    }
}
