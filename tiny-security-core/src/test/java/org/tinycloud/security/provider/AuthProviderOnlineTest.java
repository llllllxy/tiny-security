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
import org.tinycloud.security.session.OnlineSession;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;
import org.tinycloud.security.util.JsonUtil;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@code AuthProvider} 在线用户查询与定向下线的回归。
 *
 * <p>覆盖三组对外 API：{@code getOnlineLoginIds / countOnlineUsers / getOnlineSessions}、
 * 以及配套的 {@code deleteBySessionId} 与 {@code getSessionId}。
 *
 * <p><b>本类最重要的一条断言是「列表输出里绝不能出现凭证」</b>（
 * {@link #onlineSessionOutputMustNotContainCredentials()}）：在线用户列表是典型的运维后台接口，
 * 一旦把凭证带进响应体，拿到响应的人就能直接接管会话。这里不只看"类里有没有这个字段"，
 * 而是把对象<b>真的序列化一遍</b>再断言凭证串不在其中 —— 前者约束不到"将来有人加了个字段
 * 又把凭证塞回去"，后者能。
 *
 * @author liuxingyu01
 */
class AuthProviderOnlineTest {

    private SingleSessionRepository repository;
    private AuthProvider authProvider;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, new MockHttpServletResponse()));
        repository = new SingleSessionRepository();
        authProvider = new AuthProvider(repository, properties(), null);
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
        RequestContextHolder.resetRequestAttributes();
    }

    // ==================== 在线账号名单 ====================

    /**
     * 无人在线时返回空列表与 0，而不是 null 或异常。
     */
    @Test
    void emptyStateShouldReturnEmptyListAndZero() {
        assertNotNull(authProvider.getOnlineLoginIds());
        assertTrue(authProvider.getOnlineLoginIds().isEmpty());
        assertEquals(0, authProvider.countOnlineUsers());
        assertTrue(authProvider.getOnlineSessions().isEmpty());
    }

    /**
     * 在线账号名单按账号去重，账号数也按账号计（不是会话数）。
     */
    @Test
    void onlineAccountsShouldBeDeduplicated() {
        authProvider.login(10001L, null);
        authProvider.login(10001L, null);
        authProvider.login(20002L, null);

        List<Object> loginIds = authProvider.getOnlineLoginIds();
        assertEquals(2, loginIds.size(), "3 次登录、2 个账号，名单应只有 2 项，实际：" + loginIds);
        assertTrue(loginIds.contains("10001"), "统一按 String 返回，实际：" + loginIds);
        assertTrue(loginIds.contains("20002"));
        assertEquals(2, authProvider.countOnlineUsers(), "在线人数是 2，不是会话数 3");
    }

    // ==================== 会话明细与凭证安全 ====================

    /**
     * 会话明细按"份"返回（同一账号多端登录会有多条），且带出登录时写入的 extraInfo。
     */
    @Test
    void onlineSessionsShouldListEverySessionWithExtraInfo() {
        authProvider.login(10001L, Collections.singletonMap("ip", "192.168.1.10"));
        authProvider.login(10001L, Collections.singletonMap("ip", "192.168.1.11"));

        List<OnlineSession> sessions = authProvider.getOnlineSessions();
        assertEquals(2, sessions.size(), "同一账号 2 台设备应有 2 条明细，实际：" + sessions.size());
        for (OnlineSession session : sessions) {
            assertEquals(10001L, session.getLoginId());
            assertNotNull(session.getLoginTime());
            assertNotNull(session.getLoginExpireTime());
            assertNotNull(session.getExtraInfo(), "extraInfo 应原样带出（业务要用它存 IP / 设备）");
        }
        assertTrue(sessions.stream().anyMatch(s -> "192.168.1.10".equals(s.getExtraInfo().get("ip"))));
        assertTrue(sessions.stream().anyMatch(s -> "192.168.1.11".equals(s.getExtraInfo().get("ip"))));
    }

    /**
     * 【安全】序列化后的输出里绝不能出现凭证。
     *
     * <p>凭证就是 bearer token 的签名原文，等同于用户身份凭据。这里把 {@link OnlineSession}
     * 真的过一遍 JSON 序列化再断言，防止将来给这个类加字段时把凭证重新带出去。
     */
    @Test
    void onlineSessionOutputMustNotContainCredentials() {
        String token = authProvider.login(10001L, Collections.singletonMap("ip", "127.0.0.1"));
        String credentials = authProvider.getCredentialsByToken(token);

        OnlineSession session = authProvider.getOnlineSessions().get(0);

        assertFalse(JsonUtil.writeValueAsString(session).contains(credentials),
                "序列化结果里不得包含凭证：凭证等同于 bearer token，泄露即可接管会话");
        assertFalse(session.toString().contains(credentials), "toString 里也不得包含凭证");
        assertNull(fieldNamedCredentials(session), "OnlineSession 上不应存在 credentials 字段");
    }

    /**
     * 同一个凭证每次算出的会话标识必须一致 —— 否则列表里刚显示、点踢人就失效。
     */
    @Test
    void sessionIdShouldBeStableForTheSameCredentials() {
        String token = authProvider.login(10001L, null);
        String credentials = authProvider.getCredentialsByToken(token);

        String first = authProvider.getSessionIdByCredentials(credentials);
        String second = authProvider.getSessionIdByCredentials(credentials);
        assertEquals(first, second, "标识必须稳定，否则列表与踢人会对不上");
        assertEquals(64, first.length(), "SHA-256 摘要应为 64 位十六进制");
        assertEquals(first, authProvider.getOnlineSessions().get(0).getSessionId());
    }

    /**
     * 当前请求会话的标识，应当能在在线列表里对上自己那一条。
     */
    @Test
    void currentSessionIdShouldMatchItsOwnEntryInTheList() {
        String token = authProvider.login(10001L, null);
        request.addHeader("token", token);
        authProvider.login(20002L, null);

        String currentSessionId = authProvider.getSessionId();
        Optional<OnlineSession> mine = authProvider.getOnlineSessions().stream()
                .filter(s -> currentSessionId.equals(s.getSessionId()))
                .findFirst();

        assertTrue(mine.isPresent(), "当前会话必须出现在在线列表里");
        assertEquals(10001L, mine.get().getLoginId());
    }

    // ==================== 定向下线 ====================

    /**
     * 按会话标识踢人：只踢掉匹配的那一份，同账号其它设备不受影响。
     */
    @Test
    void deleteBySessionIdShouldKickOnlyTheMatchedSession() {
        authProvider.login(10001L, Collections.singletonMap("device", "pc"));
        authProvider.login(10001L, Collections.singletonMap("device", "mobile"));

        List<OnlineSession> sessions = authProvider.getOnlineSessions();
        assertEquals(2, sessions.size());
        OnlineSession pc = sessions.stream()
                .filter(s -> "pc".equals(s.getExtraInfo().get("device")))
                .findFirst().orElseThrow(() -> new IllegalStateException("pc 会话应存在"));

        assertTrue(authProvider.deleteBySessionId(10001L, pc.getSessionId()), "踢人应返回 true");

        List<OnlineSession> remaining = authProvider.getOnlineSessions();
        assertEquals(1, remaining.size(), "只应剩下一个会话");
        assertEquals("mobile", remaining.get(0).getExtraInfo().get("device"), "被踢的应是 pc 那一份");
        assertEquals(1, authProvider.countOnlineUsers(), "账号还有其它设备在线，不应从名单里消失");
    }

    /**
     * 会话标识对不上（已过期/已登出/被篡改）时返回 false，而不是误删或抛异常。
     */
    @Test
    void deleteBySessionIdShouldReturnFalseWhenNotMatched() {
        authProvider.login(10001L, null);

        assertFalse(authProvider.deleteBySessionId(10001L, "not-a-real-session-id"));
        assertFalse(authProvider.deleteBySessionId(99999L, "not-a-real-session-id"),
                "账号不存在时也应返回 false 而不是抛异常");
        assertEquals(1, authProvider.countOnlineUsers(), "误匹配不应删掉任何会话");
    }

    /**
     * 空/非法入参必须显式报错，不能被静默当成"没找到"。
     */
    @Test
    void deleteBySessionIdShouldRejectBlankArguments() {
        authProvider.login(10001L, null);
        String validSessionId = authProvider.getOnlineSessions().get(0).getSessionId();

        assertThrows(IllegalArgumentException.class, () -> authProvider.deleteBySessionId(null, validSessionId));
        assertThrows(IllegalArgumentException.class, () -> authProvider.deleteBySessionId(10001L, "  "));
        assertEquals(1, authProvider.countOnlineUsers());
    }

    /**
     * 自定义仓储未实现全局查询时，必须抛 UnsupportedOperationException 明确报错，
     * 而不是静默返回空列表让调用方误以为"没人在线"。
     */
    @Test
    void shouldPropagateUnsupportedOperationExceptionFromRepository() {
        AuthProvider provider = new AuthProvider(new UnsupportedRepository(), properties(), null);

        assertThrows(UnsupportedOperationException.class, provider::getOnlineLoginIds,
                "仓储不支持全局查询时必须明确报错，而不是静默返回空列表");
        assertThrows(UnsupportedOperationException.class, provider::countOnlineUsers);
        assertThrows(UnsupportedOperationException.class, provider::getOnlineSessions,
                "AuthProvider 不得吞掉仓储抛出的 UnsupportedOperationException");
    }

    /**
     * 反射检查 OnlineSession 上不存在 credentials 字段（结构性约束，见
     * {@link #onlineSessionOutputMustNotContainCredentials()}）。
     *
     * @param session 被测对象
     * @return 存在该字段时返回其 getter 名，否则返回 null
     */
    private static String fieldNamedCredentials(OnlineSession session) {
        for (java.lang.reflect.Method method : session.getClass().getMethods()) {
            if ("getCredentials".equals(method.getName())) {
                return method.getName();
            }
        }
        return null;
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setTokenSecret("test-token-secret-for-online-query!!");
        return properties;
    }

    /**
     * 未实现全局查询的自定义仓储（模拟用户自定义实现未重写 default 方法的情形）。
     */
    private static final class UnsupportedRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            throw new UnsupportedOperationException();
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            throw new UnsupportedOperationException();
        }
    }
}
