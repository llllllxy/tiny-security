package org.tinycloud.security.annotation;

import java.lang.reflect.Method;

/**
 * 授权注解工具类。
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
     * @return 权限注解
     */
    public static RequiresPermissions findRequiresPermissions(Method method) {
        RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiresPermissions.class);
        }
        return annotation;
    }

    /**
     * 查找Method或声明类上的@RequiresRoles注解。
     *
     * @param method Method
     * @return 角色注解
     */
    public static RequiresRoles findRequiresRoles(Method method) {
        RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiresRoles.class);
        }
        return annotation;
    }

    /**
     * 查找Method或声明类上的@Ignore注解。
     *
     * @param method Method
     * @return 忽略注解
     */
    public static Ignore findIgnore(Method method) {
        Ignore annotation = method.getAnnotation(Ignore.class);
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(Ignore.class);
        }
        return annotation;
    }
}
