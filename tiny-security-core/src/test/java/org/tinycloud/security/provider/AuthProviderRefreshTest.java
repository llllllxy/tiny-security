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
import org.tinycloud.security.session.SingleSessionRepository;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@code AuthProvider#refreshByCredentials(credentials, subject)} 的过期口径一致性。
 *
 * <p><b>缺陷</b>：该方法只把「存储层 TTL」延长为 {@code timeout}，却**从不更新
 * {@code subject.loginExpireTime}**。而 {@code 1.5.0} 给内核补上的「绝对过期校验」
 * （{@code DefaultAuthenticationManager}）判定的正是 {@code loginExpireTime} ——
 * 于是两套过期口径分叉：存储里的会话明明还有 TTL，用户却已经 401，
 * 续期看起来「没生效」。旧逻辑靠下一跳顺手续期把这条缝盖住了，所以一直没暴露。
 *
 * <p><b>修复后</b>：刷新时同步把 {@code loginExpireTime} 推进到 {@code now + timeout}，
 * 与内核自己的滑动续期路径（{@code DefaultAuthenticationManager} 先 set 再 refresh）口径一致。
 *
 * <p>注意两点用例设计上的讲究：
 * <ul>
 *     <li>刻意使用**内置** {@link SingleSessionRepository} 而非假仓储 —— 用假仓储验证可达性
 *         会得到假结论（教训）；</li>
 *     <li>{@code getSubject} 返回的是**副本**，因此不能靠「改动读出来的对象」来伪造
 *         过期状态，必须直接构造待刷新的 subject 传给 {@code refreshByCredentials}，
 *         这也正是该公开 API 的真实调用方式。</li>
 * </ul>
 *
 * @author liuxingyu01
 */
class AuthProviderRefreshTest {

    private SingleSessionRepository repository;
    private AuthProvider authProvider;

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
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
     * 核心回归：刷新必须同时推进 {@code loginExpireTime}。
     *
     * <p>修复前该时间戳保持旧值（这里刻意构造成「已过去」），于是刷新后
     * 内核的绝对过期校验依旧判 401 —— 续期等于没做。
     */
    @Test
    void refreshShouldExtendLoginExpireTime() {
        String token = authProvider.login(10001L, null);
        String credentials = credentialsOf(token);

        LoginSubject subject = repository.getSubject(credentials);
        assertNotNull(subject, "登录后应能读到会话");
        // 构造一个「时间戳已过期但存储层仍在」的会话，模拟长期未续期的登录主体
        subject.setLoginExpireTime(System.currentTimeMillis() - 1000L);

        assertTrue(authProvider.refreshByCredentials(credentials, subject), "刷新本身应成功");

        assertTrue(subject.getLoginExpireTime() > System.currentTimeMillis(),
                "刷新后 loginExpireTime 必须被推进到未来，否则绝对过期校验仍会判 401；实际 = "
                        + subject.getLoginExpireTime());
    }

    /**
     * 刷新后应当真的「续上」：以刷新写入存储的内容为准，复刻内核的判定口径不应再 401。
     *
     * <p>这条用例锁定「续期没生效」这一用户可见症状，并且通过仓储回读，
     * 确保推进后的时间戳确实**落到了存储里**（而不只是改了内存对象）。
     */
    @Test
    void refreshedSessionShouldSurviveKernelAbsoluteExpiryCheck() {
        String token = authProvider.login(10001L, null);
        String credentials = credentialsOf(token);

        LoginSubject subject = repository.getSubject(credentials);
        assertNotNull(subject);
        subject.setLoginExpireTime(System.currentTimeMillis() - 1000L);

        authProvider.refreshByCredentials(credentials, subject);

        LoginSubject afterRefresh = repository.getSubject(credentials);
        assertNotNull(afterRefresh, "刷新后存储层应仍有该会话（TTL 已延长）");
        Long expireTime = afterRefresh.getLoginExpireTime();
        assertNotNull(expireTime, "刷新后 loginExpireTime 不应为 null");
        // 复刻 DefaultAuthenticationManager：expireTime == null || expireTime <= now → 401
        assertTrue(expireTime > System.currentTimeMillis(),
                "刷新后仍会被内核判定为已过期，等于续期没生效");
    }

    /**
     * 边界：subject 为 null 时不得抛 NPE（退化为纯 TTL 延长）。
     */
    @Test
    void refreshShouldTolerateNullSubject() {
        String token = authProvider.login(10001L, null);
        String credentials = credentialsOf(token);

        assertDoesNotThrow(() -> authProvider.refreshByCredentials(credentials, null));
    }

    private static String credentialsOf(String token) {
        String signed = token.substring("Bearer ".length());
        return signed.substring(0, signed.lastIndexOf('.'));
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setTokenSecret("test-token-secret-for-refresh");
        properties.setTimeout(1800);
        return properties;
    }
}
