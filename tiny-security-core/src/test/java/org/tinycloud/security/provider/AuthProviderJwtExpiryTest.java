package org.tinycloud.security.provider;

import org.junit.jupiter.api.Test;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.JwtUtil;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthProviderJwtExpiryTest {

    private static final long ONE_DAY_MILLIS = 24L * 60 * 60 * 1000;

    /**
     * 默认情况下 jwt 自身有效期应为30天（2592000秒）。
     */
    @Test
    void shouldDefaultJwtTimeoutTo30Days() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);

        String token = authProvider.login("user-1", null);

        assertEquals(30L * ONE_DAY_MILLIS, jwtLifetimeMillis(token), 1_000L);
    }

    /**
     * 配置 jwt-timeout 且大于会话 timeout 时，按配置值生效。
     */
    @Test
    void shouldUseConfiguredJwtTimeout() {
        AuthProperties properties = defaultProperties();
        properties.setJwtTimeout(7200);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        String token = authProvider.login("user-1", null);

        assertEquals(7200_000L, jwtLifetimeMillis(token), 1_000L);
    }

    /**
     * jwt-timeout 配置得比会话 timeout 还小时，取两者较大值，避免 token 先于会话过期。
     */
    @Test
    void shouldNotLetJwtExpireBeforeSessionTimeout() {
        AuthProperties properties = defaultProperties();
        properties.setJwtTimeout(60);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        String token = authProvider.login("user-1", null);

        assertEquals(1800_000L, jwtLifetimeMillis(token), 1_000L);
    }

    /**
     * 解析登录 token 中 JWT 的实际有效期（exp - iat，毫秒）。
     */
    private long jwtLifetimeMillis(String token) {
        String jwt = token.substring("Bearer ".length());
        Map<String, String> claims = JwtUtil.getClaims("test-secret", jwt);
        assertNotNull(claims);
        return Long.parseLong(claims.get("exp")) - Long.parseLong(claims.get("iat"));
    }

    private AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setCredentialsStyle("uuid");
        properties.setMaxConcurrentLogins(0);
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
        return properties;
    }

    static class FakeSessionRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return true;
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
