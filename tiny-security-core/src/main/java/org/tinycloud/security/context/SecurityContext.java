package org.tinycloud.security.context;

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

    /**
     * 角色集合。{@code null} 表示「本次请求尚未从 AuthorizationInfoGet 加载过角色」，
     * 这与「已加载、但确实一个角色都没有」是两种不同状态——只有能区分它们，
     * 才能在「不为注解做 SPI 调用」的性能前提下，让 AuthUtil.hasRole 按需懒加载。
     */
    private Set<String> roleSet;

    /**
     * 权限集合。{@code null} 表示「本次请求尚未从 AuthorizationInfoGet 加载过权限」，语义同 {@link #roleSet}。
     */
    private Set<String> permissionSet;

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
     * @return 角色集合；尚未加载时返回空集合（调用方若需区分，用 {@link #isRoleSetLoaded()}）
     */
    public Set<String> getRoleSet() {
        return this.roleSet == null ? Collections.emptySet() : this.roleSet;
    }

    /**
     * 判断本次请求的角色集合是否已从数据源加载过。
     *
     * @return true-已加载（可能确实为空集）；false-尚未加载，可由上层按需加载
     */
    public boolean isRoleSetLoaded() {
        return this.roleSet != null;
    }

    /**
     * 设置角色集合，空值会被转换为空集合（即同时标记为「已加载」）。
     *
     * @param roleSet 角色集合
     */
    public void setRoleSet(Set<String> roleSet) {
        this.roleSet = roleSet == null ? Collections.emptySet() : roleSet;
    }

    /**
     * 获取权限集合。
     *
     * @return 权限集合；尚未加载时返回空集合（调用方若需区分，用 {@link #isPermissionSetLoaded()}）
     */
    public Set<String> getPermissionSet() {
        return this.permissionSet == null ? Collections.emptySet() : this.permissionSet;
    }

    /**
     * 判断本次请求的权限集合是否已从数据源加载过。
     *
     * @return true-已加载（可能确实为空集）；false-尚未加载，可由上层按需加载
     */
    public boolean isPermissionSetLoaded() {
        return this.permissionSet != null;
    }

    /**
     * 设置权限集合，空值会被转换为空集合（即同时标记为「已加载」）。
     *
     * @param permissionSet 权限集合
     */
    public void setPermissionSet(Set<String> permissionSet) {
        this.permissionSet = permissionSet == null ? Collections.emptySet() : permissionSet;
    }
}
