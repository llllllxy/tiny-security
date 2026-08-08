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
import org.tinycloud.security.context.ThreadLocalSecurityContextHolder;
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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationInterceptorTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
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

    @Test
    void shouldSkipAuthorizationWhenNoAuthorizationAnnotationInAnnotationMode() throws Exception {
        AuthorizationInterceptor interceptor = buildInterceptor(PermissionMode.ANNOTATION, emptyAuthorizationInfo(), new CapturingSecurityEventPublisher());
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        ThreadLocalSecurityContextHolder.setContext(context);

        boolean allowed = interceptor.preHandle(
                request(),
                new MockHttpServletResponse(),
                handlerMethod("plain")
        );

        assertTrue(allowed);
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
        ThreadLocalSecurityContextHolder.setContext(context);
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
