package org.tinycloud.security;

import jakarta.servlet.http.HttpServletRequest;
import org.tinycloud.security.authorization.AuthorizationEvaluator;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
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
 * <p><b>1.3.4 行为统一</b>：所有 {@code get*} 与 {@code has*} 方法在未登录/会话失效时统一抛
 * {@link UnAuthorizedException}（与 {@link AuthProvider} 对齐），不再返回 null。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
public class TinySecurityFacade {

    private final SecurityContextRepository securityContextRepository;

    /**
     * 角色权限数据提供器；可能为 null（未提供时 getRoleSet/getPermissionSet 只返回上下文中已有的数据）。
     */
    private final AuthorizationInfoGet authorizationInfoGet;

    /**
     * 构造安全门面（不含角色权限数据源）。
     *
     * <p>该重载下 {@link #getRoleSet()} / {@link #getPermissionSet()} 只返回上下文中已有的数据，
     * 不做按需懒加载。需要 {@code AuthUtil.hasRole/hasPermission} 在任何接口上都能正确判断时，
     * 请使用 {@link #TinySecurityFacade(SecurityContextRepository, AuthorizationInfoGet)}。
     *
     * @param securityContextRepository 安全上下文仓储
     */
    public TinySecurityFacade(SecurityContextRepository securityContextRepository) {
        this(securityContextRepository, null);
    }

    /**
     * 构造安全门面。
     *
     * @param securityContextRepository 安全上下文仓储
     * @param authorizationInfoGet      角色权限数据提供者，可为 null
     */
    public TinySecurityFacade(SecurityContextRepository securityContextRepository, AuthorizationInfoGet authorizationInfoGet) {
        this.securityContextRepository = securityContextRepository;
        this.authorizationInfoGet = authorizationInfoGet;
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     * @throws UnAuthorizedException 无请求上下文或未登录/会话失效时抛出（与 {@link AuthProvider#getSecurityContext()} 语义统一）
     */
    public SecurityContext getSecurityContext() {
        HttpServletRequest request = WebRequestUtils.getRequest();
        if (request != null && securityContextRepository != null) {
            SecurityContext context = securityContextRepository.loadContext(request);
            if (context != null && context.getLoginSubject() != null) {
                return context;
            }
        }
        throw new UnAuthorizedException();
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体
     * @throws UnAuthorizedException 未登录时
     */
    public LoginSubject getLoginSubject() {
        return this.getSecurityContext().getLoginSubject();
    }

    /**
     * 获取当前登录账号ID。
     *
     * @return 登录账号ID
     * @throws UnAuthorizedException 未登录时
     */
    public Object getLoginId() {
        return this.getLoginSubject().getLoginId();
    }

    /**
     * 获取当前登录账号ID（字符串形式）。
     *
     * @return 字符串账号ID
     * @throws UnAuthorizedException 未登录时
     */
    public String getLoginIdAsString() {
        return String.valueOf(this.getLoginId());
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID
     * @throws UnAuthorizedException 未登录时
     * @throws TinySecurityException loginId 非数字时
     */
    public Integer getLoginIdAsInt() {
        Object loginId = this.getLoginId();
        try {
            return Integer.parseInt(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Integer: " + loginId);
        }
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID
     * @throws UnAuthorizedException 未登录时
     * @throws TinySecurityException loginId 非数字时
     */
    public Long getLoginIdAsLong() {
        Object loginId = this.getLoginId();
        try {
            return Long.parseLong(String.valueOf(loginId));
        } catch (NumberFormatException e) {
            throw new TinySecurityException("loginId cannot be parsed as Long: " + loginId);
        }
    }

    /**
     * 获取当前角色集合。
     *
     * <p><b>按需懒加载</b>：若本次请求尚未加载过角色（典型场景是接口上没有权限注解、
     * 授权管理器因此没为注解做 SPI 调用），这里会向 {@link AuthorizationInfoGet} 查询一次，
     * 并把结果缓存回本次请求的上下文——后续调用不会重复查询。
     *
     * @return 角色集合
     * @throws UnAuthorizedException 未登录时
     */
    public Set<String> getRoleSet() {
        SecurityContext context = this.getSecurityContext();
        if (!context.isRoleSetLoaded() && this.authorizationInfoGet != null) {
            context.setRoleSet(this.authorizationInfoGet.getRoleSet(context.getLoginSubject()));
        }
        return context.getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * <p><b>按需懒加载</b>：语义同 {@link #getRoleSet()}，只查询并缓存权限集合。
     *
     * @return 权限集合
     * @throws UnAuthorizedException 未登录时
     */
    public Set<String> getPermissionSet() {
        SecurityContext context = this.getSecurityContext();
        if (!context.isPermissionSetLoaded() && this.authorizationInfoGet != null) {
            context.setPermissionSet(this.authorizationInfoGet.getPermissionSet(context.getLoginSubject()));
        }
        return context.getPermissionSet();
    }

    /**
     * 判断当前账号是否拥有指定角色。
     *
     * @param role 角色标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasRole(String role) {
        return AuthorizationEvaluator.hasRole(getRoleSet(), role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAllRole(String... roles) {
        return AuthorizationEvaluator.hasAllRole(getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAnyRole(String... roles) {
        return AuthorizationEvaluator.hasAnyRole(getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有指定权限。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasPermission(String permission) {
        return AuthorizationEvaluator.hasPermission(getPermissionSet(), permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAllPermission(String... permissions) {
        return AuthorizationEvaluator.hasAllPermission(getPermissionSet(), permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAnyPermission(String... permissions) {
        return AuthorizationEvaluator.hasAnyPermission(getPermissionSet(), permissions);
    }
}
