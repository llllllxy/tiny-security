package org.tinycloud.security.provider;

import org.junit.jupiter.api.Test;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.SessionRepository;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 会话超时语义（P1-8）。
 *
 * <p>修复前 {@code tiny-security.timeout} 没有任何校验，非正值落到四个仓储上会分别表现为
 * 永不过期（single）/ 立即驱逐（caffeine）/ 登录失败（redis）/ 立即过期（jdbc）。
 * 现在只允许「正数」或未配置（null，沿用 1800 秒默认值），**任何非正值都在装配阶段直接拒绝**。
 *
 * <p>说明：曾短暂支持过 {@code timeout = -1} 表示"永不过期"，现已取消 —— 会话永不过期对安全框架
 * 是反模式（凭证泄露后永无失效），且会让"存储层 TTL"与"loginExpireTime"两套过期口径分叉。
 *
 * @author liuxingyu01
 */
class AuthProviderTimeoutTest {

    /**
     * timeout = 0 是最常见的「漏配/手滑」值，必须在装配阶段就报错。
     */
    @Test
    void shouldRejectZeroTimeout() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new AuthProvider(new RecordingSessionRepository(), propertiesWithTimeout(0), null));
        assertTrue(ex.getMessage().contains("tiny-security.timeout"), "报错信息必须指向具体的配置项：" + ex.getMessage());
    }

    /**
     * -1 曾经表示"永不过期"，现已取消：它同样必须被拒绝。
     * <p>这条用例是本次决策的锁定点 —— 防止将来有人重新引入 -1 语义。
     */
    @Test
    void shouldRejectNeverExpireTimeout() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new AuthProvider(new RecordingSessionRepository(), propertiesWithTimeout(-1), null));
        assertTrue(ex.getMessage().contains("tiny-security.timeout"), "报错信息必须指向具体的配置项：" + ex.getMessage());
    }

    /**
     * 其余负值（如 -2）同样非法：修复前它在 caffeine 上是「立即驱逐」，在 redis 上是「登录失败」。
     */
    @Test
    void shouldRejectOtherNegativeTimeout() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new AuthProvider(new RecordingSessionRepository(), propertiesWithTimeout(-2), null));
        assertTrue(ex.getMessage().contains("tiny-security.timeout"), "报错信息必须指向具体的配置项：" + ex.getMessage());
    }

    /**
     * 正数与未配置都能正常装配。
     */
    @Test
    void shouldAcceptPositiveAndNullTimeout() {
        assertNotNull(new AuthProvider(new RecordingSessionRepository(), propertiesWithTimeout(60), null));
        assertNotNull(new AuthProvider(new RecordingSessionRepository(), propertiesWithTimeout(null), null));
    }

    /**
     * 未配置 timeout 时沿用 1800 秒默认值（与修复前一致）。
     */
    @Test
    void shouldFallBackToDefaultTimeoutWhenNull() {
        RecordingSessionRepository repository = new RecordingSessionRepository();
        AuthProvider provider = new AuthProvider(repository, propertiesWithTimeout(null), null);

        long before = System.currentTimeMillis();
        String token = provider.login("user-1", new HashMap<>());
        long after = System.currentTimeMillis();

        assertNotNull(token);
        assertTrue(repository.saved.getLoginExpireTime() >= before + 1_800_000L
                        && repository.saved.getLoginExpireTime() <= after + 1_800_000L,
                "未配置 timeout 时应按 1800 秒计算过期时间，实际：" + repository.saved.getLoginExpireTime());
    }

    /**
     * 配置的正数必须原样下传仓储，并据此铸造 loginExpireTime（不能被默认值覆盖）。
     */
    @Test
    void shouldMintExpireTimeFromConfiguredTimeout() {
        RecordingSessionRepository repository = new RecordingSessionRepository();
        AuthProvider provider = new AuthProvider(repository, propertiesWithTimeout(60), null);

        long before = System.currentTimeMillis();
        provider.login("user-1", new HashMap<>());
        long after = System.currentTimeMillis();

        assertEquals(60, repository.savedTimeoutSeconds);
        assertTrue(repository.saved.getLoginExpireTime() >= before + 60_000L
                        && repository.saved.getLoginExpireTime() <= after + 60_000L,
                "应按 60 秒计算过期时间，实际：" + repository.saved.getLoginExpireTime());
    }

    private static AuthProperties propertiesWithTimeout(Integer timeout) {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTokenSecret("test-secret");
        properties.setTimeout(timeout);
        return properties;
    }

    /**
     * 只记录调用结果的会话仓储，用于断言框架传下来的 timeout 与铸造出的过期时间。
     */
    static class RecordingSessionRepository implements SessionRepository {
        LoginSubject saved;
        int savedTimeoutSeconds;

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            this.saved = subject;
            this.savedTimeoutSeconds = timeoutSeconds;
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
            return false;
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            return false;
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            return 0;
        }
    }
}
