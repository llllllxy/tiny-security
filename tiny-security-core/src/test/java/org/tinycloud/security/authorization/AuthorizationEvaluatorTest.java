package org.tinycloud.security.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.tinycloud.security.annotation.RequiresPermissions;
import org.tinycloud.security.annotation.RequiresRoles;
import org.tinycloud.security.enums.Logical;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 授权计算工具类测试。
 *
 * <p>覆盖权限/角色判定、`*` 通配符模糊匹配、Ant 风格 URL 匹配三大核心逻辑。
 */
class AuthorizationEvaluatorTest {

    // ---------------- vagueMatch 通配符匹配 ----------------

    @Test
    void vagueMatchShouldSupportAsteriskWildcard() {
        assertTrue(AuthorizationEvaluator.vagueMatch("user*", "user-add"));
        assertTrue(AuthorizationEvaluator.vagueMatch("user*", "user"));
        assertFalse(AuthorizationEvaluator.vagueMatch("user*", "art-add"));
        assertFalse(AuthorizationEvaluator.vagueMatch("user*", "my-user"));
    }

    @Test
    void vagueMatchShouldTreatDotAsLiteral() {
        assertTrue(AuthorizationEvaluator.vagueMatch("art.*", "art.add"));
        // `*` 可匹配空串，但 `.` 是字面量必须匹配：art.* 匹配 art.，但不匹配 art
        assertTrue(AuthorizationEvaluator.vagueMatch("art.*", "art."));
        assertFalse(AuthorizationEvaluator.vagueMatch("art.*", "art"));
        assertFalse(AuthorizationEvaluator.vagueMatch("art.*", "art-add"));
        assertFalse(AuthorizationEvaluator.vagueMatch("art.*", "cart.add"));
    }

    @Test
    void vagueMatchShouldHandleMultipleAsterisks() {
        assertTrue(AuthorizationEvaluator.vagueMatch("a*b*c", "aXbYc"));
        assertTrue(AuthorizationEvaluator.vagueMatch("a*b*c", "abc"));
        assertFalse(AuthorizationEvaluator.vagueMatch("a*b*c", "aXbY"));
    }

    @Test
    void vagueMatchShouldHandleNull() {
        assertTrue(AuthorizationEvaluator.vagueMatch(null, null));
        assertFalse(AuthorizationEvaluator.vagueMatch(null, "x"));
        assertFalse(AuthorizationEvaluator.vagueMatch("x", null));
    }

    @Test
    void vagueMatchShouldUseEqualsWhenNoWildcard() {
        assertTrue(AuthorizationEvaluator.vagueMatch("user:read", "user:read"));
        assertFalse(AuthorizationEvaluator.vagueMatch("user:read", "user:write"));
    }

    // ---------------- hasElement 集合匹配 ----------------

    @Test
    void hasElementShouldMatchExactOrWildcard() {
        Set<String> permissions = new HashSet<>(Arrays.asList("user:read", "order:*", "report:view"));

        assertTrue(AuthorizationEvaluator.hasElement(permissions, "user:read"));
        assertTrue(AuthorizationEvaluator.hasElement(permissions, "order:create"));
        assertTrue(AuthorizationEvaluator.hasElement(permissions, "report:view"));
        assertFalse(AuthorizationEvaluator.hasElement(permissions, "user:delete"));
        assertFalse(AuthorizationEvaluator.hasElement(permissions, "inventory:view"));
    }

    @Test
    void hasElementShouldReturnFalseForEmptyOrNullCollection() {
        assertFalse(AuthorizationEvaluator.hasElement(null, "x"));
        assertFalse(AuthorizationEvaluator.hasElement(Collections.emptySet(), "x"));
    }

    // ---------------- hasRole / hasPermission 系列 ----------------

    @Test
    void hasRoleShouldSupportAndOrSemantics() {
        Set<String> roles = new HashSet<>(Arrays.asList("admin", "user"));

        assertTrue(AuthorizationEvaluator.hasRole(roles, "admin"));
        assertFalse(AuthorizationEvaluator.hasRole(roles, "guest"));
        assertTrue(AuthorizationEvaluator.hasAllRole(roles, "admin", "user"));
        assertFalse(AuthorizationEvaluator.hasAllRole(roles, "admin", "guest"));
        assertTrue(AuthorizationEvaluator.hasAnyRole(roles, "admin", "guest"));
        assertFalse(AuthorizationEvaluator.hasAnyRole(roles, "guest", "root"));
    }

    @Test
    void hasPermissionShouldSupportAndOrSemantics() {
        Set<String> permissions = new HashSet<>(Arrays.asList("user:read", "user:write"));

        assertTrue(AuthorizationEvaluator.hasPermission(permissions, "user:read"));
        assertFalse(AuthorizationEvaluator.hasPermission(permissions, "user:delete"));
        assertTrue(AuthorizationEvaluator.hasAllPermission(permissions, "user:read", "user:write"));
        assertFalse(AuthorizationEvaluator.hasAllPermission(permissions, "user:read", "user:delete"));
        assertTrue(AuthorizationEvaluator.hasAnyPermission(permissions, "user:read", "user:delete"));
        assertFalse(AuthorizationEvaluator.hasAnyPermission(permissions, "user:delete", "user:export"));
    }

    // ---------------- checkPermission / checkRole（注解驱动） ----------------

    @Test
    void checkPermissionShouldHonorAndLogical() throws Exception {
        Method method = AnnotatedController.class.getMethod("andPermission");
        Set<String> permissions = new HashSet<>(Arrays.asList("p1", "p2"));

        assertTrue(AuthorizationEvaluator.checkPermission(method, permissions));
        assertFalse(AuthorizationEvaluator.checkPermission(method, new HashSet<>(Arrays.asList("p1"))));
        assertFalse(AuthorizationEvaluator.checkPermission(method, new HashSet<>(Arrays.asList("p2"))));
    }

    @Test
    void checkPermissionShouldHonorOrLogical() throws Exception {
        Method method = AnnotatedController.class.getMethod("orPermission");
        Set<String> permissions = new HashSet<>(Arrays.asList("p1"));

        assertTrue(AuthorizationEvaluator.checkPermission(method, permissions));
        assertFalse(AuthorizationEvaluator.checkPermission(method, new HashSet<>(Arrays.asList("p3"))));
    }

    @Test
    void checkPermissionShouldPassWhenNoAnnotationOrEmptyValue() throws Exception {
        Method noAnnotation = AnnotatedController.class.getMethod("plain");
        Method empty = AnnotatedController.class.getMethod("emptyPermission");

        assertTrue(AuthorizationEvaluator.checkPermission(noAnnotation, Collections.emptySet()));
        assertTrue(AuthorizationEvaluator.checkPermission(empty, Collections.emptySet()));
    }

    @Test
    void checkRoleShouldHonorAndOrLogical() throws Exception {
        Method andMethod = AnnotatedController.class.getMethod("andRole");
        Method orMethod = AnnotatedController.class.getMethod("orRole");

        assertTrue(AuthorizationEvaluator.checkRole(andMethod, new HashSet<>(Arrays.asList("r1", "r2"))));
        assertFalse(AuthorizationEvaluator.checkRole(andMethod, new HashSet<>(Arrays.asList("r1"))));
        assertTrue(AuthorizationEvaluator.checkRole(orMethod, new HashSet<>(Arrays.asList("r1"))));
        assertFalse(AuthorizationEvaluator.checkRole(orMethod, new HashSet<>(Arrays.asList("r3"))));
    }

    // ---------------- matchPaths（Ant 风格 URL 匹配） ----------------

    @Test
    void matchPathsShouldSupportAntPatterns() {
        assertTrue(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/**")), "/user/list"));
        assertTrue(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/user/*")), "/user/list"));
        assertFalse(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/user/*")), "/user/list/1"));
        assertTrue(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/user/**")), "/user/list/1"));
        assertTrue(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/order/{id}")), "/order/42"));
        assertFalse(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/order/{id}")), "/order/42/items"));
        assertFalse(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/admin/*")), "/user/list"));
    }

    @Test
    void matchPathsShouldReturnFalseForEmptyOrNull() {
        assertFalse(AuthorizationEvaluator.matchPaths(null, "/x"));
        assertFalse(AuthorizationEvaluator.matchPaths(Collections.emptySet(), "/x"));
        assertFalse(AuthorizationEvaluator.matchPaths(new HashSet<>(Arrays.asList("/x")), ""));
    }

    // ---------------- checkUrlPermission（URL 模式鉴权） ----------------

    @Test
    void checkUrlPermissionShouldMatchRequestUriAgainstPermissionSet() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/user/list");

        assertTrue(AuthorizationEvaluator.checkUrlPermission(request, new HashSet<>(Arrays.asList("/user/**"))));
        assertTrue(AuthorizationEvaluator.checkUrlPermission(request, new HashSet<>(Arrays.asList("/user/list"))));
        assertFalse(AuthorizationEvaluator.checkUrlPermission(request, new HashSet<>(Arrays.asList("/admin/**"))));
        assertFalse(AuthorizationEvaluator.checkUrlPermission(request, Collections.emptySet()));
    }

    @Test
    void checkUrlPermissionShouldReturnFalseForNullRequest() {
        assertFalse(AuthorizationEvaluator.checkUrlPermission(null, new HashSet<>(Arrays.asList("/**"))));
    }

    // ---------------- 测试用注解控制器 ----------------

    @SuppressWarnings("unused")
    static class AnnotatedController {

        @RequiresPermissions(value = {"p1", "p2"}, logical = Logical.AND)
        public void andPermission() {
        }

        @RequiresPermissions(value = {"p1", "p2"}, logical = Logical.OR)
        public void orPermission() {
        }

        @RequiresPermissions(value = {})
        public void emptyPermission() {
        }

        @RequiresRoles(value = {"r1", "r2"}, logical = Logical.AND)
        public void andRole() {
        }

        @RequiresRoles(value = {"r1", "r2"}, logical = Logical.OR)
        public void orRole() {
        }

        public void plain() {
        }
    }
}
