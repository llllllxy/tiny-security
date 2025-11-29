package org.tinycloud.security.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.annotation.Ignore;
import org.tinycloud.security.annotation.RequiresPermissions;
import org.tinycloud.security.annotation.RequiresRoles;
import org.tinycloud.security.enums.Logical;
import org.tinycloud.security.interceptor.holder.AuthenticeHolder;
import org.tinycloud.security.interceptor.holder.PermissionHolder;
import org.tinycloud.security.interceptor.holder.RoleHolder;
import org.tinycloud.security.provider.LoginSubject;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Set;

public class AuthUtil {

    /**
     * 获取当前请求对象
     *
     * @return HttpServletRequest
     */
    public static HttpServletRequest getRequest() {
        try {
            return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取当前响应对象
     *
     * @return HttpServletResponse
     */
    public static HttpServletResponse getResponse() {
        try {
            return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * 获取用户token
     *
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(String tokenName) {
        HttpServletRequest request = getRequest();
        return request == null ? null : getToken(request, tokenName);
    }


    /**
     * 获取用户token
     *
     * @param request   HttpServletRequest
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(HttpServletRequest request, String tokenName) {
        // 从请求中获取token，先从Header里取
        String token = request.getHeader(tokenName);
        // 取不到的话再从cookie里取（适配前后端分离的模式）
        if (!StringUtils.hasText(token)) {
            token = CookieUtil.getCookie(request, tokenName);
        }
        // cookie里取不到，再从请求参数里面取
        if (!StringUtils.hasText(token)) {
            token = request.getParameter(tokenName);
        }
        return token;
    }


    /**
     * 检查Method上是否有@Ignore注解，决定是否忽略会话认证
     *
     * @param method Method
     * @return true or false
     */
    public static boolean checkIgnore(Method method) {
        // 先获取方法上的注解
        Ignore annotation = method.getAnnotation(Ignore.class);
        // 方法上没有注解再检查类上面有没有注解
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(Ignore.class);
        }
        return annotation != null;
    }

    /**
     * 判断是否有权限注解
     *
     * @param method Method
     * @return true有 or false没有
     */
    public static boolean hasPermissionAnnotation(Method method) {
        // 检查方法上的 @RequiresPermissions
        RequiresPermissions permAnnotation = method.getAnnotation(RequiresPermissions.class);
        if (permAnnotation != null) {
            return true;
        }
        // 检查类上的 @RequiresPermissions
        permAnnotation = method.getDeclaringClass().getAnnotation(RequiresPermissions.class);
        if (permAnnotation != null) {
            return true;
        }
        // 检查方法上的 @RequiresRoles
        RequiresRoles roleAnnotation = method.getAnnotation(RequiresRoles.class);
        if (roleAnnotation != null) {
            return true;
        }
        // 检查类上的 @RequiresRoles
        roleAnnotation = method.getDeclaringClass().getAnnotation(RequiresRoles.class);
        return roleAnnotation != null;
    }

    /**
     * url自动匹配权限模式（无需加注解了，只支持权限的校验，不支持角色）
     * 此处是按照全路径匹配的，所以在设置权限编码时，如有contextPath，则也需要带上contextPath
     *
     * <p>
     * 当一个账号拥有 `/**` 权限时，可以验证通过任何权限路径（超级管理员权限）
     * </p>
     *
     * @param request HttpServletRequest
     * @return true or false
     */
    public static boolean checkUrlPermission(HttpServletRequest request) {
        String path = request.getRequestURI();
        Set<String> permissionSet = PermissionHolder.getPermissionSet();
        // 当permissionSet为空时，说明无任何权限，直接返回false
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        return CommonUtil.matchPaths(permissionSet, path);
    }


    /**
     * 检查Method上是否有@RequiresPermissions注解，并检验其值，通过返回true，拒绝返回false
     *
     * @param method Method
     * @return true or false
     */
    public static boolean checkPermission(Method method) {
        RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
        // 方法上没有注解再检查类上面有没有注解
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiresPermissions.class);
        }
        // 接口上没有注解，说明这个接口无需权限控制，直接通过
        if (annotation == null) {
            return true;
        }
        // 当roles为空时，说明不需要任何权限，直接返回true
        String[] permissions = annotation.value();
        if (ObjectUtils.isEmpty(permissions)) {
            return true;
        }
        Logical logical = annotation.logical();
        if (logical == Logical.OR) {
            return hasAnyPermission(permissions);
        } else if (logical == Logical.AND) {
            return hasAllPermission(permissions);
        } else {
            return false;
        }
    }


    /**
     * 检查Method上是否有@RequiresRoles注解，并检验其值，通过返回true，拒绝返回false
     *
     * @param method Method
     * @return true or false
     */
    public static boolean checkRole(Method method) {
        RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
        // 方法上没有注解再检查类上面有没有注解
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiresRoles.class);
        }
        // 接口上没有注解，说明这个接口无权限控制，直接通过
        if (annotation == null) {
            return true;
        }
        // 当roles为空时，说明不需要任何权限，直接返回true
        String[] roles = annotation.value();
        if (ObjectUtils.isEmpty(roles)) {
            return true;
        }
        Logical logical = annotation.logical();
        if (logical == Logical.OR) {
            return hasAnyRole(roles);
        } else if (logical == Logical.AND) {
            return hasAllRole(roles);
        } else {
            return false;
        }
    }


    /**
     * 获取当前登录用户的LoginId
     *
     * @return Object
     */
    public static Object getLoginId() {
        LoginSubject subject = getLoginSubject();
        return subject == null ? null : subject.getLoginId();
    }

    /**
     * 获取当前登录用户的loginId, 并转换为 String 类型
     *
     * @return 账号id
     */
    public static String getLoginIdAsString() {
        Object loginId = getLoginId();
        return loginId == null ? null : String.valueOf(loginId);
    }

    /**
     * 获取当前登录用户的loginId, 并转换为 Integer 类型
     *
     * @return 账号id
     */
    public static Integer getLoginIdAsInt() {
        Object loginId = getLoginId();
        return loginId == null ? null : Integer.parseInt(String.valueOf(loginId));
    }

    /**
     * 获取当前登录用户的loginId, 并转换为 Long 类型
     *
     * @return 账号id
     */
    public static Long getLoginIdAsLong() {
        Object loginId = getLoginId();
        return loginId == null ? null : Long.parseLong(String.valueOf(loginId));
    }

    /**
     * 获取当前登录用户的LoginId
     *
     * @return Object
     */
    public static LoginSubject getLoginSubject() {
        return AuthenticeHolder.getLoginSubject();
    }


    /**
     * 手动判断拥有角色：role1
     *
     * @return true or false
     */
    public static boolean hasRole(String role) {
        Set<String> roleSet = RoleHolder.getRoleSet();
        // 当roleSet为空时，说明无任何权限，直接返回false
        if (roleSet == null || roleSet.isEmpty()) {
            return false;
        }
        return hasElement(roleSet, role);
    }

    /**
     * 手动判断拥有角色：role1 and role2
     *
     * @param roles 角色列表
     * @return true or false
     */
    public static boolean hasAllRole(String... roles) {
        Set<String> roleSet = RoleHolder.getRoleSet();
        // 当roleSet为空时，说明无任何权限，直接返回false
        if (roleSet == null || roleSet.isEmpty()) {
            return false;
        }
        // 只要有一个角色不是true的，就返回false（同时拥有）
        for (String ro : roles) {
            if (!hasElement(roleSet, ro)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 手动判断拥有角色：role1 or role2 or role3 有其一即可
     *
     * @param roles 角色列表
     * @return true or false
     */
    public static boolean hasAnyRole(String... roles) {
        Set<String> roleSet = RoleHolder.getRoleSet();
        // 当roleSet为空时，说明无任何权限，直接返回false
        if (roleSet == null || roleSet.isEmpty()) {
            return false;
        }
        // 如果有任何一个角色，返回true，否则返回false（拥有其一）
        for (String ro : roles) {
            if (hasElement(roleSet, ro)) {
                return true;
            }
        }
        return false;
    }


    /**
     * 手动判断拥有权限：permission1
     *
     * @return true or false
     */
    public static boolean hasPermission(String permission) {
        Set<String> permissionSet = PermissionHolder.getPermissionSet();
        // 当permissionSet为空时，说明无任何权限，直接返回false
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        return hasElement(permissionSet, permission);
    }

    /**
     * 手动判断拥有角色：permission1 and permission2
     *
     * @param permissions 权限列表
     * @return true or false
     */
    public static boolean hasAllPermission(String... permissions) {
        Set<String> permissionSet = PermissionHolder.getPermissionSet();
        // 当permissionSet为空时，说明无任何权限，直接返回false
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        // 只要有一个权限不是true的，就返回false（同时拥有）
        for (String pe : permissions) {
            if (!hasElement(permissionSet, pe)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 手动判断拥有权限：permission1 or permission2 or permission3 有其一即可
     *
     * @param permissions 权限列表
     * @return true or false
     */
    public static boolean hasAnyPermission(String... permissions) {
        Set<String> permissionSet = PermissionHolder.getPermissionSet();
        // 当permissionSet为空时，说明无任何权限，直接返回false
        if (permissionSet == null || permissionSet.isEmpty()) {
            return false;
        }
        // 如果有任何一个权限，返回true，否则返回false（拥有其一）
        for (String pe : permissions) {
            if (hasElement(permissionSet, pe)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断集合中是否包含某个元素，支持模糊匹配
     *
     * @param list    集合列表
     * @param element 元素
     * @return true匹配成功 or false匹配失败
     */
    private static boolean hasElement(Collection<String> list, String element) {
        // 空集合直接返回false
        if (list == null || list.isEmpty()) {
            return false;
        }
        // 先尝试一下简单匹配，如果可以匹配成功则无需继续模糊匹配
        if (list.contains(element)) {
            return true;
        }
        // 开始模糊匹配
        for (String pattern : list) {
            if (CommonUtil.vagueMatch(pattern, element)) {
                return true;
            }
        }
        // 走出for循环说明没有一个元素可以匹配成功
        return false;
    }

}
