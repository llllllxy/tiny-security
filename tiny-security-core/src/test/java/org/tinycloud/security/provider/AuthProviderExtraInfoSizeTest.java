package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.session.SingleSessionRepository;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 登录时对 {@code extraInfo} 大小的约束。
 *
 * <p><b>问题</b>：{@code extraInfo} 会被序列化进整个 {@code LoginSubject}，而 jdbc 仓储把它存进
 * {@code t_auth_storage.login_subject varchar(5000)}。此前没有任何长度校验 —— 用户塞入超大的
 * extraInfo 后，只有在**切到 jdbc 仓储**时才会失败，而且报错是一条不直观的 SQL 错误；
 * 在 single / caffeine / redis 下则会静默成功，等于把问题推迟到换存储时才爆。
 *
 * <p><b>修复后</b>：登录时先做一次序列化长度检查，超限直接抛出指向 {@code extraInfo} 的明确错误。
 *
 * @author liuxingyu01
 */
class AuthProviderExtraInfoSizeTest {

    private SingleSessionRepository repository;
    private AuthProvider authProvider;

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
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

    /**
     * 正常大小的 extraInfo 不受影响。
     */
    @Test
    void shouldAcceptNormalExtraInfo() {
        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("nickname", "张三");
        extraInfo.put("tenantId", 1001L);

        String token = authProvider.login(10001L, extraInfo);

        assertNotNull(token);
        assertEquals(extraInfo.get("nickname"), repository.getSubject(credentialsOf(token)).getExtraInfo().get("nickname"));
    }

    /**
     * 超长的 extraInfo 必须在登录时就失败，且错误信息要能指向 extraInfo 与上限。
     */
    @Test
    void shouldRejectOversizedExtraInfo() {
        Map<String, Object> extraInfo = new HashMap<>();
        // 单个值就远超 5000 字符上限
        extraInfo.put("blob", repeat('x', 6000));

        TinySecurityException ex = assertThrows(TinySecurityException.class,
                () -> authProvider.login(10001L, extraInfo));

        String message = ex.getMessage();
        assertTrue(message.contains("extraInfo"), "报错应指向 extraInfo，实际：" + message);
        assertTrue(message.contains("5000"), "报错应给出上限值，实际：" + message);
    }

    /**
     * 超长登录不应留下任何会话（失败的登录必须是干净的失败）。
     */
    @Test
    void failedLoginShouldNotCreateSession() {
        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("blob", repeat('x', 6000));

        assertThrows(TinySecurityException.class, () -> authProvider.login(10001L, extraInfo));

        assertEquals(0, repository.countValidOnlineSessions(10001L), "超长登录不应创建会话");
    }

    /**
     * 边界：恰好在上限内的内容仍应可用（避免把校验写成一刀切的误杀）。
     */
    @Test
    void shouldAcceptExtraInfoJustUnderLimit() {
        Map<String, Object> extraInfo = new HashMap<>();
        // 留出序列化开销（字段名、时间戳等约几百字符），取 4000 保证落在 5000 以内
        extraInfo.put("blob", repeat('x', 4000));

        assertDoesNotThrow(() -> authProvider.login(10001L, extraInfo));
    }

    private static String repeat(char c, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    private static String credentialsOf(String token) {
        String signed = token.substring("Bearer ".length());
        return signed.substring(0, signed.lastIndexOf('.'));
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setTokenSecret("test-token-secret-for-extra-info-size!!");
        return properties;
    }
}
