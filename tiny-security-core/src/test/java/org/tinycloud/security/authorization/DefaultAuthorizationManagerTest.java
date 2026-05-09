package org.tinycloud.security.authorization;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.annotation.RequiresPermissions;
import org.tinycloud.security.annotation.RequiresRoles;
import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.ThreadLocalSecurityContextHolder;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.context.LoginSubject;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAuthorizationManagerTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        GlobalConfigUtils.clearGlobalConfig();
    }

    @Test
    void shouldGrantPlainMethodInAnnotationMode() throws Exception {
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(PermissionMode.ANNOTATION, emptyAuthorizationInfo());

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo"), method("plain"), null);

        assertTrue(decision.isGranted());
    }

    @Test
    void shouldTreatNullPermissionModeAsAnnotationMode() throws Exception {
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(null, emptyAuthorizationInfo());

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo"), method("plain"), null);

        assertTrue(decision.isGranted());
    }

    @Test
    void shouldDenyWhenProtectedMethodHasNoPermissionData() throws Exception {
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(PermissionMode.ANNOTATION, emptyAuthorizationInfo());

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo"), method("secured"), null);

        assertFalse(decision.isGranted());
    }

    @Test
    void shouldReturnForbiddenWhenPermissionMissing() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(PermissionMode.ANNOTATION, emptyAuthorizationInfo());
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo"), method("secured"), context);

        assertFalse(decision.isGranted());
    }

    @Test
    void shouldGrantWhenPermissionAndRoleMatch() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("admin-1");
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(
                PermissionMode.ANNOTATION,
                new AuthorizationInfoGet() {
                    @Override
                    public Set<String> getPermissionSet(LoginSubject subject) {
                        return Collections.singleton("user:read");
                    }

                    @Override
                    public Set<String> getRoleSet(LoginSubject subject) {
                        return Collections.singleton("admin");
                    }
                }
        );
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo"), method("securedWithRole"), context);

        assertTrue(decision.isGranted());
    }

    @Test
    void shouldGrantWhenUrlPermissionMatchesInUrlMode() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        DefaultAuthorizationManager authorizationManager = new DefaultAuthorizationManager(
                PermissionMode.URL,
                new AuthorizationInfoGet() {
                    @Override
                    public Set<String> getPermissionSet(LoginSubject subject) {
                        return Collections.singleton("/demo/**");
                    }

                    @Override
                    public Set<String> getRoleSet(LoginSubject subject) {
                        return Collections.emptySet();
                    }
                }
        );
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);

        AuthorizationDecision decision = authorizationManager.authorize(request("/demo/list"), method("plain"), context);

        assertTrue(decision.isGranted());
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

    private MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI(uri);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setBanner(false);
        globalConfig.setSecurityContextRepository(new ThreadLocalSecurityContextRepository());
        GlobalConfigUtils.setGlobalConfig(globalConfig);
        return request;
    }

    private Method method(String name) throws NoSuchMethodException {
        return TestController.class.getMethod(name);
    }

    static class TestController {
        public void plain() {
        }

        @RequiresPermissions("user:read")
        public void secured() {
        }

        @RequiresPermissions("user:read")
        @RequiresRoles("admin")
        public void securedWithRole() {
        }
    }
}
