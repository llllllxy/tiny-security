package org.tinycloud.security.provider;

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
 * 当前请求的上下文与授权判定实现，是 {@link AuthProvider} 的内部基类。
 *
 * <p><b>1.5.0 起本类不再是公开 API</b>：此前它是独立的公开门面，并由 {@code AuthUtil} 通过一个
 * 可变静态变量（{@code AuthUtil.setFacade}）反向持有，而那个赋值点位于
 * {@code @ConditionalOnMissingBean(TinySecurityFacade.class)} 的 Bean 方法内 —— 用户一旦自定义
 * 门面 Bean，静态变量就永远不会被赋值，{@code AuthUtil} 与 {@code AuthProvider.getSecurityContext()}
 * 会一起失效（P1-1 / P1-2）。现在改为：本类仅供 {@link AuthProvider} 继承，外部请直接使用
 * {@link AuthProvider}（唯一实例门面）或 {@code AuthUtil}（静态便捷外观）。
 *
 * <p><b>1.3.4 行为统一</b>：所有 {@code get*} 与 {@code has*} 方法在未登录/会话失效时统一抛
 * {@link UnAuthorizedException}（与 {@link AuthProvider} 对齐），不再返回 null。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
class TinySecurityFacade {

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
    TinySecurityFacade(SecurityContextRepository securityContextRepository) {
        this(securityContextRepository, null);
    }

    /**
     * 构造安全门面。
     *
     * @param securityContextRepository 安全上下文仓储
     * @param authorizationInfoGet      角色权限数据提供者，可为 null
     */
    TinySecurityFacade(SecurityContextRepository securityContextRepository, AuthorizationInfoGet authorizationInfoGet) {
        this.securityContextRepository = securityContextRepository;
        this.authorizationInfoGet = authorizationInfoGet;
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     * @throws UnAuthorizedException 无请求上下文或未登录/会话失效时抛出
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
        return AuthorizationEvaluator.hasRole(this.getRoleSet(), role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAllRole(String... roles) {
        return AuthorizationEvaluator.hasAllRole(this.getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAnyRole(String... roles) {
        return AuthorizationEvaluator.hasAnyRole(this.getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有指定权限。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasPermission(String permission) {
        return AuthorizationEvaluator.hasPermission(this.getPermissionSet(), permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAllPermission(String... permissions) {
        return AuthorizationEvaluator.hasAllPermission(this.getPermissionSet(), permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录时
     */
    public boolean hasAnyPermission(String... permissions) {
        return AuthorizationEvaluator.hasAnyPermission(this.getPermissionSet(), permissions);
    }
}
