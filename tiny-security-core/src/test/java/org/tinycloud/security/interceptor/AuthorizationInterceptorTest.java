package org.tinycloud.security.interceptor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.tinycloud.security.annotation.Ignore;
import org.tinycloud.security.annotation.RequiresPermissions;
import org.tinycloud.security.authorization.AuthorizationManager;
import org.tinycloud.security.authorization.DefaultAuthorizationManager;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.event.AuthorizationFailureEvent;
import org.tinycloud.security.event.LoginFailureEvent;
import org.tinycloud.security.event.LoginSuccessEvent;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationInterceptorTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextRepository.clearContext();
    }

    @Test
    void shouldSkipAuthorizationWhenIgnoreAnnotationPresent() throws Exception {
        AuthorizationInterceptor interceptor = buildInterceptor(PermissionMode.ANNOTATION, emptyAuthorizationInfo(), new CapturingSecurityEventPublisher());

        boolean allowed = interceptor.preHandle(
                request(),
                new MockHttpServletResponse(),
                handlerMethod("ignored")
        );

        assertTrue(allowed);
    }

    /**
     * ANNOTATION 模式且方法无权限注解时直接放行，**并且不为本次请求调用 SPI**
     * ——这是 1.3.1 引入的性能设计，必须保留（否则每个请求都要白白多查一次角色/权限）。
     *
     * <p>正因为这里不加载，{@code AuthUtil.hasRole/hasPermission} 才必须能在上下文缺数据时
     * 按需懒加载（P0-1 的根因与修复见 {@code TinySecurityFacade#getRoleSet}）。
     */
    @Test
    void shouldSkipAuthorizationAndSkipSpiCallWhenNoAuthorizationAnnotationInAnnotationMode() throws Exception {
        AtomicInteger roleQueryCount = new AtomicInteger();
        AtomicInteger permissionQueryCount = new AtomicInteger();
        AuthorizationInterceptor interceptor = buildInterceptor(PermissionMode.ANNOTATION,
                countingAuthorizationInfo(roleQueryCount, permissionQueryCount), new CapturingSecurityEventPublisher());
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        ThreadLocalSecurityContextRepository.setContext(context);

        boolean allowed = interceptor.preHandle(
                request(),
                new MockHttpServletResponse(),
                handlerMethod("plain")
        );

        assertTrue(allowed);
        // 无注解 → 不查 SPI；上下文保持「未加载」，把加载时机留给 AuthUtil.has* 按需触发
        assertEquals(0, roleQueryCount.get());
        assertEquals(0, permissionQueryCount.get());
        assertFalse(context.isRoleSetLoaded());
        assertFalse(context.isPermissionSetLoaded());
    }

    @Test
    void shouldThrowUnauthorizedWhenProtectedMethodHasNoAuthenticatedSubject() throws Exception {
        AuthorizationInterceptor interceptor = buildInterceptor(PermissionMode.ANNOTATION, emptyAuthorizationInfo(), new CapturingSecurityEventPublisher());

        assertThrows(UnAuthorizedException.class, () -> interceptor.preHandle(
                request(),
                new MockHttpServletResponse(),
                handlerMethod("secured")
        ));
    }

    @Test
    void shouldThrowNoPermissionWhenSubjectLacksRequiredPermission() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        ThreadLocalSecurityContextRepository.setContext(context);
        CapturingSecurityEventPublisher eventPublisher = new CapturingSecurityEventPublisher();
        AuthorizationInterceptor interceptor = buildInterceptor(PermissionMode.ANNOTATION, emptyAuthorizationInfo(), eventPublisher);

        assertThrows(NoPermissionException.class, () -> interceptor.preHandle(
                request(),
                new MockHttpServletResponse(),
                handlerMethod("secured")
        ));
        assertTrue(eventPublisher.authorizationFailureCount.get() > 0);
    }

    private AuthorizationInterceptor buildInterceptor(PermissionMode permissionMode, AuthorizationInfoGet authorizationInfoGet, SecurityEventPublisher securityEventPublisher) {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setPermCheckMode(permissionMode);
        AuthorizationManager authorizationManager = new DefaultAuthorizationManager(permissionMode, authorizationInfoGet);
        ThreadLocalSecurityContextRepository scr = new ThreadLocalSecurityContextRepository();
        return new AuthorizationInterceptor(authorizationManager, scr, securityEventPublisher, properties);
    }

    private AuthorizationInfoGet emptyAuthorizationInfo() {
        return new AuthorizationInfoGet() {
            @Override
            public Set<String> getPermissionSet(LoginSubject subject) {
                return Collections.emptySet();
            }

            @Override
            public Set<String> getRoleSet(LoginSubject subject) {
                return Collections.emptySet();
            }
        };
    }

    /**
     * 会累加查询次数的角色权限数据源，用于验证「不该查的时候一次都不查」。
     */
    private AuthorizationInfoGet countingAuthorizationInfo(AtomicInteger roleQueryCount, AtomicInteger permissionQueryCount) {
        return new AuthorizationInfoGet() {
            @Override
            public Set<String> getPermissionSet(LoginSubject subject) {
                permissionQueryCount.incrementAndGet();
                return Collections.emptySet();
            }

            @Override
            public Set<String> getRoleSet(LoginSubject subject) {
                roleQueryCount.incrementAndGet();
                return Collections.emptySet();
            }
        };
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/demo");
        return request;
    }

    private HandlerMethod handlerMethod(String methodName) throws NoSuchMethodException {
        Method method = TestController.class.getMethod(methodName);
        return new HandlerMethod(new TestController(), method);
    }

    static class TestController {
        @Ignore
        public void ignored() {
        }

        public void plain() {
        }

        @RequiresPermissions("user:read")
        public void secured() {
        }
    }

    static class CapturingSecurityEventPublisher implements SecurityEventPublisher {
        private final AtomicInteger authorizationFailureCount = new AtomicInteger(0);

        @Override
        public void publishLoginSuccess(LoginSuccessEvent event) {
        }

        @Override
        public void publishLoginFailure(LoginFailureEvent event) {
        }

        @Override
        public void publishAuthorizationFailure(AuthorizationFailureEvent event) {
            authorizationFailureCount.incrementAndGet();
        }
    }
}
