package org.tinycloud.security;

import jakarta.servlet.http.HttpServletRequest;
import org.tinycloud.security.authorization.AuthorizationEvaluator;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.web.WebRequestUtils;

import java.util.Set;

/**
 * 安全门面：持有运行时依赖，为 {@link AuthUtil} 等静态工具类提供委托目标。
 *
 * <p>设计参照 Sa-Token 的 StpUtil/StpLogic 模式：
 * <ul>
 *     <li>本类是 Spring Bean，通过构造注入获取依赖，可测试、可替换</li>
 *     <li>{@link AuthUtil} 是静态外观，delegate 到本类的实例</li>
 *     <li>用户侧调用方式（AuthUtil.getLoginId() 等）完全不变</li>
 * </ul>
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
public class TinySecurityFacade {

    private final SecurityContextRepository securityContextRepository;

    /**
     * 构造安全门面。
     *
     * @param securityContextRepository 安全上下文仓储
     */
    public TinySecurityFacade(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文，无请求或无会话时返回 null
     */
    public SecurityContext getSecurityContext() {
        HttpServletRequest request = WebRequestUtils.getRequest();
        if (request != null && securityContextRepository != null) {
            return securityContextRepository.loadContext(request);
        }
        return null;
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体，无会话时返回 null
     */
    public LoginSubject getLoginSubject() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getLoginSubject();
    }

    /**
     * 获取当前登录账号ID。
     *
     * @return 登录账号ID，无会话时返回 null
     */
    public Object getLoginId() {
        LoginSubject subject = getLoginSubject();
        return subject == null ? null : subject.getLoginId();
    }

    /**
     * 获取当前登录账号ID（字符串形式）。
     *
     * @return 字符串账号ID，无会话时返回 null
     */
    public String getLoginIdAsString() {
        Object loginId = getLoginId();
        return loginId == null ? null : String.valueOf(loginId);
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID，无会话时返回 null；loginId 非数字时抛 {@link TinySecurityException}
     */
    public Integer getLoginIdAsInt() {
        Object loginId = getLoginId();
        if (loginId == null) {
            return null;
        }
        try {
            return Integer.parseInt(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Integer: " + loginId);
        }
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID，无会话时返回 null；loginId 非数字时抛 {@link TinySecurityException}
     */
    public Long getLoginIdAsLong() {
        Object loginId = getLoginId();
        if (loginId == null) {
            return null;
        }
        try {
            return Long.parseLong(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Long: " + loginId);
        }
    }

    /**
     * 获取当前角色集合。
     *
     * @return 角色集合，无会话时返回 null
     */
    public Set<String> getRoleSet() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * @return 权限集合，无会话时返回 null
     */
    public Set<String> getPermissionSet() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getPermissionSet();
    }

    /**
     * 判断当前账号是否拥有指定角色。
     *
     * @param role 角色标识
     * @return true-拥有，false-未拥有
     */
    public boolean hasRole(String role) {
        return AuthorizationEvaluator.hasRole(getRoleSet(), role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     */
    public boolean hasAllRole(String... roles) {
        return AuthorizationEvaluator.hasAllRole(getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     */
    public boolean hasAnyRole(String... roles) {
        return AuthorizationEvaluator.hasAnyRole(getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有指定权限。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     */
    public boolean hasPermission(String permission) {
        return AuthorizationEvaluator.hasPermission(getPermissionSet(), permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     */
    public boolean hasAllPermission(String... permissions) {
        return AuthorizationEvaluator.hasAllPermission(getPermissionSet(), permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     */
    public boolean hasAnyPermission(String... permissions) {
        return AuthorizationEvaluator.hasAnyPermission(getPermissionSet(), permissions);
    }
}
