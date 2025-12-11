package org.tinycloud.security.interceptor.holder;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * 本地线程变量-缓存用户权限资源值信息
 *
 * @author liuxingyu01
 * @since 2023-06-04 13:58
 **/
public class AuthorizationHolder {
    private final static ThreadLocal<Set<String>> roleSetLocal = new ThreadLocal<>();
    private final static ThreadLocal<Set<String>> permissionSetLocal = new ThreadLocal<>();

    public static Set<String> getPermissionSet() {
        Set<String> permissionSet = permissionSetLocal.get();
        if (Objects.isNull(permissionSet)) {
            return new HashSet<String>();
        } else {
            return permissionSet;
        }
    }

    public static void setPermissionSet(Set<String> loginId) {
        permissionSetLocal.set(loginId);
    }

    public static void clearPermissionSet() {
        permissionSetLocal.remove();
    }

    public static Set<String> getRoleSet() {
        Set<String> roleSet = roleSetLocal.get();
        if (Objects.isNull(roleSet)) {
            return new HashSet<String>();
        } else {
            return roleSet;
        }
    }

    public static void setRoleSet(Set<String> loginId) {
        roleSetLocal.set(loginId);
    }

    public static void clearRoleSet() {
        roleSetLocal.remove();
    }
}
