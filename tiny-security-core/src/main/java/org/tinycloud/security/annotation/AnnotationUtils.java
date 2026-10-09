package org.tinycloud.security.annotation;

import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;

/**
 * 授权注解工具类。
 *
 * <p>查找语义为「方法 → 方法的父类/接口同名方法 → 方法声明类 → 声明类的父类/接口」，
 * 并支持组合注解（元注解）。这样做是因为：若只认「方法本身 + 声明类本身」，
 * 那么注解写在父类或接口上、方法在子类里被重写 / 实现时会查不到注解，
 * 授权拦截器会把接口判定成「无注解接口」并**直接放行** —— 属于安全方向的静默失效。
 *
 * @author liuxingyu01
 * @since 2026-05-26
 */
public final class AnnotationUtils {

    /**
     * 禁止实例化授权注解工具类。
     */
    private AnnotationUtils() {
    }

    /**
     * 检查Method上是否存在@Ignore注解。
     *
     * @param method Method
     * @return true-存在，false-不存在
     */
    public static boolean checkIgnore(Method method) {
        return findIgnore(method) != null;
    }

    /**
     * 判断Method上是否存在授权注解。
     *
     * @param method Method
     * @return true-存在，false-不存在
     */
    public static boolean hasAuthorizationAnnotation(Method method) {
        return findRequiresPermissions(method) != null || findRequiresRoles(method) != null;
    }

    /**
     * 查找Method或声明类上的@RequiresPermissions注解。
     *
     * @param method Method
     * @return 权限注解；未找到返回 null
     */
    public static RequiresPermissions findRequiresPermissions(Method method) {
        RequiresPermissions annotation = AnnotatedElementUtils.findMergedAnnotation(method, RequiresPermissions.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), RequiresPermissions.class);
        }
        return annotation;
    }

    /**
     * 查找Method或声明类上的@RequiresRoles注解。
     *
     * @param method Method
     * @return 角色注解；未找到返回 null
     */
    public static RequiresRoles findRequiresRoles(Method method) {
        RequiresRoles annotation = AnnotatedElementUtils.findMergedAnnotation(method, RequiresRoles.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), RequiresRoles.class);
        }
        return annotation;
    }

    /**
     * 查找Method或声明类上的@Ignore注解。
     *
     * @param method Method
     * @return 忽略注解；未找到返回 null
     */
    public static Ignore findIgnore(Method method) {
        Ignore annotation = AnnotatedElementUtils.findMergedAnnotation(method, Ignore.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), Ignore.class);
        }
        return annotation;
    }
}
