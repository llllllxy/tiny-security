package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setJwtSecret("test-jwt-secret-for-credentials-lookup");
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
