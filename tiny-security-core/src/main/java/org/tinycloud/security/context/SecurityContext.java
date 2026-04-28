package org.tinycloud.security.context;

import org.tinycloud.security.provider.LoginSubject;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

/**
 * 安全上下文，统一保存当前请求的认证与授权信息
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class SecurityContext implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private LoginSubject loginSubject;
    private Set<String> roleSet = Collections.emptySet();
    private Set<String> permissionSet = Collections.emptySet();

    /**
     * 获取登录主体。
     *
     * @return 登录主体
     */
    public LoginSubject getLoginSubject() {
        return loginSubject;
    }

    /**
     * 设置登录主体。
     *
     * @param loginSubject 登录主体
     */
    public void setLoginSubject(LoginSubject loginSubject) {
        this.loginSubject = loginSubject;
    }

    /**
     * 获取角色集合。
     *
     * @return 角色集合
     */
    public Set<String> getRoleSet() {
        return roleSet;
    }

    /**
     * 设置角色集合，空值会被转换为空集合。
     *
     * @param roleSet 角色集合
     */
    public void setRoleSet(Set<String> roleSet) {
        this.roleSet = roleSet == null ? Collections.emptySet() : roleSet;
    }

    /**
     * 获取权限集合。
     *
     * @return 权限集合
     */
    public Set<String> getPermissionSet() {
        return permissionSet;
    }

    /**
     * 设置权限集合，空值会被转换为空集合。
     *
     * @param permissionSet 权限集合
     */
    public void setPermissionSet(Set<String> permissionSet) {
        this.permissionSet = permissionSet == null ? Collections.emptySet() : permissionSet;
    }
}
