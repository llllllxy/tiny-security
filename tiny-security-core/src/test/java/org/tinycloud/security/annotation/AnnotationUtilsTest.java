package org.tinycloud.security.annotation;

import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link AnnotationUtils} 的注解查找测试。
 *
 * <p>重点覆盖「注解写在父类 / 接口上，方法却在子类里被重写或实现」这一类场景。
 * 这类场景一旦查不到注解，授权拦截器会把接口判定成「无注解接口」并**直接放行**，
 * 属于安全方向的静默失效（fail-open），因此必须有可证伪的用例守着。
 *
 * @author liuxingyu01
 */
class AnnotationUtilsTest {

    // ------------------------------------------------------------------
    // 测试用的类层次：权限注解写在父类 / 接口上，子类只重写或实现方法
    // ------------------------------------------------------------------

    @RequiresPermissions("base:read")
    @RequiresRoles("base-role")
    static class AnnotatedBaseController {

        public void inherited() {
        }

        public void overridden() {
        }
    }

    /**
     * 只继承、不重写：反射拿到的 Method 其声明类就是父类。
     */
    static class InheritedController extends AnnotatedBaseController {
    }

    /**
     * 重写了父类方法，但自己没有再标注任何注解。
     */
    static class OverridingController extends AnnotatedBaseController {

        @Override
        public void overridden() {
        }
    }

    interface PermissionedApi {

        @RequiresPermissions("api:read")
        @RequiresRoles("api-role")
        void list();
    }

    /**
     * 实现了带注解的接口方法，实现类方法上没有注解。
     */
    static class PermissionedApiImpl implements PermissionedApi {

        @Override
        public void list() {
        }
    }

    /**
     * 组合注解：自身带权限注解，业务代码只标这一层。
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @RequiresPermissions("composed:read")
    @interface ComposedPermission {
    }

    static class ComposedAnnotationController {

        @ComposedPermission
        public void list() {
        }
    }

    /**
     * 组合 {@link Ignore} 的注解。
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @Ignore
    @interface PublicApi {
    }

    static class ComposedIgnoreController {

        @PublicApi
        public void list() {
        }
    }

    /**
     * 父类被 @Ignore 标注，子类重写方法屏蔽注解。
     */
    @Ignore
    static class IgnoredBaseController {

        public void overridden() {
        }
    }

    static class OverridingIgnoredController extends IgnoredBaseController {

        @Override
        public void overridden() {
        }
    }

    private static Method method(Class<?> type, String name) throws NoSuchMethodException {
        return type.getMethod(name);
    }

    // ------------------------------------------------------------------
    // 基线：原本就生效的两种写法，修复后必须继续生效
    // ------------------------------------------------------------------

    @Test
    void shouldFindAnnotationOnMethodItself() throws Exception {
        Method method = method(DirectlyAnnotatedController.class, "list");

        assertArrayEquals(new String[]{"direct:read"},
                AnnotationUtils.findRequiresPermissions(method).value());
        assertArrayEquals(new String[]{"direct-role"},
                AnnotationUtils.findRequiresRoles(method).value());
        assertTrue(AnnotationUtils.hasAuthorizationAnnotation(method));
    }

    static class DirectlyAnnotatedController {

        @RequiresPermissions("direct:read")
        @RequiresRoles("direct-role")
        public void list() {
        }
    }

    @Test
    void shouldFindAnnotationOnDeclaringClass() throws Exception {
        // 方法未重写时，反射拿到的 Method 声明类就是父类，父类注解理应生效
        Method method = method(InheritedController.class, "inherited");
        assertNull(method.getAnnotation(RequiresPermissions.class), "前提：方法自身没有标注");
        assertEquals(AnnotatedBaseController.class, method.getDeclaringClass(),
                "前提：继承未重写时，Method 的声明类即父类");
        assertNotNull(method.getDeclaringClass().getAnnotation(RequiresPermissions.class),
                "前提：父类上的 @RequiresPermissions 可直接读到（无需上溯）");

        assertArrayEquals(new String[]{"base:read"},
                AnnotationUtils.findRequiresPermissions(method).value());
        assertArrayEquals(new String[]{"base-role"},
                AnnotationUtils.findRequiresRoles(method).value());
    }

    @Test
    void shouldFindIgnoreOnDeclaringClass() throws Exception {
        Method method = method(InheritedController.class, "inherited");
        assertNull(method.getAnnotation(Ignore.class));
        // 父类没有 @Ignore，这里只断言「不误判」
        assertFalse(AnnotationUtils.checkIgnore(method));
    }

    // ------------------------------------------------------------------
    // fail-open：以下三种写法原先都查不到注解 → 授权拦截器直接放行
    // ------------------------------------------------------------------

    @Test
    void shouldFindAnnotationOnOverriddenMethodFromSuperclass() throws Exception {
        Method method = method(OverridingController.class, "overridden");
        assertNull(method.getAnnotation(RequiresPermissions.class),
                "前提：重写的方法自身没有标注，且方法注解不继承");
        assertNull(method.getDeclaringClass().getAnnotation(RequiresPermissions.class),
                "前提：重写后声明类变成子类，getAnnotation 不沿父类上溯");

        assertNotNull(AnnotationUtils.findRequiresPermissions(method),
                "重写父类方法后应沿父类上溯找到 @RequiresPermissions");
        assertArrayEquals(new String[]{"base:read"},
                AnnotationUtils.findRequiresPermissions(method).value());
        assertNotNull(AnnotationUtils.findRequiresRoles(method),
                "重写父类方法后应沿父类上溯找到 @RequiresRoles");
        assertTrue(AnnotationUtils.hasAuthorizationAnnotation(method));
    }

    @Test
    void shouldFindAnnotationOnImplementedInterfaceMethod() throws Exception {
        Method method = method(PermissionedApiImpl.class, "list");
        assertNull(method.getAnnotation(RequiresPermissions.class),
                "前提：实现类方法自身没有标注，且方法注解不随实现继承");

        assertNotNull(AnnotationUtils.findRequiresPermissions(method),
                "实现接口方法后应沿接口上溯找到 @RequiresPermissions");
        assertArrayEquals(new String[]{"api:read"},
                AnnotationUtils.findRequiresPermissions(method).value());
        assertNotNull(AnnotationUtils.findRequiresRoles(method),
                "实现接口方法后应沿接口上溯找到 @RequiresRoles");
        assertTrue(AnnotationUtils.hasAuthorizationAnnotation(method));
    }

    @Test
    void shouldFindMetaAnnotationOnMethod() throws Exception {
        Method method = method(ComposedAnnotationController.class, "list");
        assertNull(method.getAnnotation(RequiresPermissions.class),
                "前提：方法上标的是组合注解，不是 @RequiresPermissions 本身");

        assertNotNull(AnnotationUtils.findRequiresPermissions(method),
                "组合注解（元注解）上声明的 @RequiresPermissions 应被识别");
        assertArrayEquals(new String[]{"composed:read"},
                AnnotationUtils.findRequiresPermissions(method).value());
        assertTrue(AnnotationUtils.hasAuthorizationAnnotation(method));
    }

    @Test
    void shouldFindIgnoreOnOverriddenMethodFromSuperclass() throws Exception {
        Method method = method(OverridingIgnoredController.class, "overridden");
        assertNull(method.getAnnotation(Ignore.class));
        assertNull(method.getDeclaringClass().getAnnotation(Ignore.class));

        assertTrue(AnnotationUtils.checkIgnore(method),
                "重写父类方法后应沿父类上溯找到 @Ignore");
        assertNotNull(AnnotationUtils.findIgnore(method));
    }

    @Test
    void shouldFindMetaIgnoreAnnotation() throws Exception {
        Method method = method(ComposedIgnoreController.class, "list");

        assertTrue(AnnotationUtils.checkIgnore(method),
                "组合注解（元注解）上声明的 @Ignore 应被识别");
    }

    // ------------------------------------------------------------------
    // 反向：真的没有注解时不能误判成有
    // ------------------------------------------------------------------

    @Test
    void shouldNotFindAnnotationWhenAbsentAnywhere() throws Exception {
        Method method = method(PlainController.class, "list");

        assertNull(AnnotationUtils.findRequiresPermissions(method));
        assertNull(AnnotationUtils.findRequiresRoles(method));
        assertNull(AnnotationUtils.findIgnore(method));
        assertFalse(AnnotationUtils.hasAuthorizationAnnotation(method));
        assertFalse(AnnotationUtils.checkIgnore(method));
    }

    static class PlainController {

        public void list() {
        }
    }
}
