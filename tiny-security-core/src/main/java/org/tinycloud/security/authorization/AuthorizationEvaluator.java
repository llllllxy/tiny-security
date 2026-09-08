package org.tinycloud.security.authorization;

import javax.servlet.http.HttpServletRequest;
import org.springframework.util.*;
import org.tinycloud.security.annotation.AnnotationUtils;
import org.tinycloud.security.annotation.RequiresPermissions;
import org.tinycloud.security.annotation.RequiresRoles;
import org.tinycloud.security.enums.Logical;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Set;

/**
 * 授权计算工具类。
 *
 * @author liuxingyu01
 * @since 2026-05-26
 */
public final class AuthorizationEvaluator {

    /**
     * AntPathMatcher 中的方法是线程安全的，通常建议在应用中共享同一个实例以减少开销：
     */
    private static final PathMatcher MATCHER = new AntPathMatcher();


    /**
     * 禁止实例化授权计算工具类。
     */
    private AuthorizationEvaluator() {
    }

    /**
     * 使用指定权限集合校验当前请求路径是否有访问权限。
     *
     * @param request       HTTP请求
     * @param permissionSet 权限集合
     * @return true-有权限，false-无权限
     */
    public static boolean checkUrlPermission(HttpServletRequest request, Set<String> permissionSet) {
        if (request == null) {
            return false;
        }
        String path = request.getRequestURI();
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        return matchPaths(permissionSet, path);
    }

    /**
     * 使用指定权限集合检查Method上的@RequiresPermissions注解。
     *
     * @param method        Method
     * @param permissionSet 权限集合
     * @return true-通过，false-拒绝
     */
    public static boolean checkPermission(Method method, Set<String> permissionSet) {
        RequiresPermissions annotation = AnnotationUtils.findRequiresPermissions(method);
        if (annotation == null) {
            return true;
        }
        String[] permissions = annotation.value();
        if (ObjectUtils.isEmpty(permissions)) {
            return true;
        }
        Logical logical = annotation.logical();
        if (logical == Logical.OR) {
            return hasAnyPermission(permissionSet, permissions);
        } else if (logical == Logical.AND) {
            return hasAllPermission(permissionSet, permissions);
        } else {
            return false;
        }
    }

    /**
     * 使用指定角色集合检查Method上的@RequiresRoles注解。
     *
     * @param method  Method
     * @param roleSet 角色集合
     * @return true-通过，false-拒绝
     */
    public static boolean checkRole(Method method, Set<String> roleSet) {
        RequiresRoles annotation = AnnotationUtils.findRequiresRoles(method);
        if (annotation == null) {
            return true;
        }
        String[] roles = annotation.value();
        if (ObjectUtils.isEmpty(roles)) {
            return true;
        }
        Logical logical = annotation.logical();
        if (logical == Logical.OR) {
            return hasAnyRole(roleSet, roles);
        } else if (logical == Logical.AND) {
            return hasAllRole(roleSet, roles);
        } else {
            return false;
        }
    }

    /**
     * 判断指定角色集合中是否包含目标角色。
     *
     * @param roleSet 角色集合
     * @param role    目标角色
     * @return true-包含，false-不包含
     */
    public static boolean hasRole(Set<String> roleSet, String role) {
        return hasElement(roleSet, role);
    }

    /**
     * 判断指定角色集合中是否包含全部目标角色。
     *
     * @param roleSet 角色集合
     * @param roles   目标角色列表
     * @return true-全部包含，false-未全部包含
     */
    public static boolean hasAllRole(Set<String> roleSet, String... roles) {
        if (roleSet == null || roleSet.isEmpty()) {
            return false;
        }
        for (String role : roles) {
            if (!hasElement(roleSet, role)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 判断指定角色集合中是否包含任意目标角色。
     *
     * @param roleSet 角色集合
     * @param roles   目标角色列表
     * @return true-包含任意一个，false-全部不包含
     */
    public static boolean hasAnyRole(Set<String> roleSet, String... roles) {
        if (roleSet == null || roleSet.isEmpty()) {
            return false;
        }
        for (String role : roles) {
            if (hasElement(roleSet, role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断指定权限集合中是否包含目标权限。
     *
     * @param permissionSet 权限集合
     * @param permission    目标权限
     * @return true-包含，false-不包含
     */
    public static boolean hasPermission(Set<String> permissionSet, String permission) {
        return hasElement(permissionSet, permission);
    }

    /**
     * 判断指定权限集合中是否包含全部目标权限。
     *
     * @param permissionSet 权限集合
     * @param permissions   目标权限列表
     * @return true-全部包含，false-未全部包含
     */
    public static boolean hasAllPermission(Set<String> permissionSet, String... permissions) {
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        for (String permission : permissions) {
            if (!hasElement(permissionSet, permission)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 判断指定权限集合中是否包含任意目标权限。
     *
     * @param permissionSet 权限集合
     * @param permissions   目标权限列表
     * @return true-包含任意一个，false-全部不包含
     */
    public static boolean hasAnyPermission(Set<String> permissionSet, String... permissions) {
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        for (String permission : permissions) {
            if (hasElement(permissionSet, permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断集合中是否包含目标元素，支持模糊匹配。
     *
     * @param list    集合列表
     * @param element 目标元素
     * @return true-匹配成功，false-匹配失败
     */
    public static boolean hasElement(Collection<String> list, String element) {
        if (list == null || list.isEmpty()) {
            return false;
        }
        if (list.contains(element)) {
            return true;
        }
        for (String pattern : list) {
            if (vagueMatch(pattern, element)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 字符串模糊匹配
     * <p> example:
     * <p> user* user-add   --  true
     * <p> user* art-add    --  false
     * <p> art.* art.add    --  true
     * <p> art.* art-add    --  false
     *
     * @param pattern 表达式
     * @param str     待匹配的字符串
     * @return 是否可以匹配
     */
    public static boolean vagueMatch(String pattern, String str) {
        // 两者均为 null 时，直接返回 true
        if (pattern == null && str == null) {
            return true;
        }
        // 两者其一为 null 时，直接返回 false
        if (pattern == null || str == null) {
            return false;
        }
        // 如果表达式不带有*号，则只需简单equals即可 (这样可以使速度提升200倍左右)
        if (!pattern.contains("*")) {
            return pattern.equals(str);
        }
        // 深入匹配
        return vagueMatchMethod(pattern, str);
    }

    /**
     * 字符串模糊匹配
     *
     * @param pattern 表达式
     * @param str     待匹配的字符串
     * @return 是否可以匹配
     */
    private static boolean vagueMatchMethod(String pattern, String str) {
        int m = str.length();
        int n = pattern.length();
        boolean[][] dp = new boolean[m + 1][n + 1];
        dp[0][0] = true;
        for (int i = 1; i <= n; ++i) {
            if (pattern.charAt(i - 1) == '*') {
                dp[0][i] = true;
            } else {
                break;
            }
        }
        for (int i = 1; i <= m; ++i) {
            for (int j = 1; j <= n; ++j) {
                if (pattern.charAt(j - 1) == '*') {
                    dp[i][j] = dp[i][j - 1] || dp[i - 1][j];
                } else if (str.charAt(i - 1) == pattern.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                }
            }
        }
        return dp[m][n];
    }


    /**
     * 匹配配置路径集合和当前请求路径(基于spring自带的AntPathMatcher，支持spring通配符'{}','*','**','?')
     *
     * @param configPaths 配置路径
     * @param requestPath 请求路径
     * @return false未匹配成功 true匹配成功
     */
    public static boolean matchPaths(Collection<String> configPaths, String requestPath) {
        if (CollectionUtils.isEmpty(configPaths) || !StringUtils.hasLength(requestPath)) {
            return false;
        }
        for (String configPath : configPaths) {
            if (StringUtils.hasLength(configPath) && MATCHER.match(configPath, requestPath)) {
                return true;
            }
        }
        return false;
    }
}
