package org.tinycloud.security.util;

import org.tinycloud.security.TinySecurityFacade;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.exception.UnAuthorizedException;

import java.util.Set;

/**
 * 常用对外会话便捷工具类。
 *
 * <p>静态外观模式：delegate 到 {@link TinySecurityFacade}（Spring Bean），
 * 用户调用方式不变，但内部依赖可通过注入替换，便于测试。
 *
 * <p><b>1.4.0 行为统一</b>：所有 {@code get*} 与 {@code has*} 方法在未登录/会话失效时统一抛
 * {@link UnAuthorizedException}（不再返回 null），与 {@code AuthProvider} 语义对齐。
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class AuthUtil {

    private static volatile TinySecurityFacade facade;

    /**
     * 注册门面实例（由 AuthAutoConfiguration 在启动时调用）。
     *
     * @param facade 安全门面
     */
    public static void setFacade(TinySecurityFacade facade) {
        AuthUtil.facade = facade;
    }

    /**
     * 获取门面实例。
     *
     * @return 安全门面
     * @throws IllegalStateException 门面未初始化时（tiny-security 未正确配置）
     */
    public static TinySecurityFacade getFacade() {
        if (facade == null) {
            throw new IllegalStateException("TinySecurityFacade not initialized. " +
                    "Please ensure tiny-security is properly configured.");
        }
        return facade;
    }

    /**
     * 获取当前登录账号ID。
     *
     * @return 登录账号ID（Number 或 String，由登录时传入的 loginId 决定）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Object getLoginId() {
        return getFacade().getLoginId();
    }

    /**
     * 获取当前登录账号ID（字符串形式）。
     *
     * @return 字符串账号ID
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static String getLoginIdAsString() {
        return getFacade().getLoginIdAsString();
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID
     * @throws UnAuthorizedException         未登录或会话失效时
     * @throws org.tinycloud.security.exception.TinySecurityException loginId 非数字时
     */
    public static Integer getLoginIdAsInt() {
        return getFacade().getLoginIdAsInt();
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID
     * @throws UnAuthorizedException         未登录或会话失效时
     * @throws org.tinycloud.security.exception.TinySecurityException loginId 非数字时
     */
    public static Long getLoginIdAsLong() {
        return getFacade().getLoginIdAsLong();
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static SecurityContext getSecurityContext() {
        return getFacade().getSecurityContext();
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体（含 loginId、凭证、扩展信息等）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static LoginSubject getLoginSubject() {
        return getFacade().getLoginSubject();
    }

    /**
     * 获取当前角色集合。
     *
     * @return 角色集合（可能为空集合）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Set<String> getRoleSet() {
        return getFacade().getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * @return 权限集合（可能为空集合）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Set<String> getPermissionSet() {
        return getFacade().getPermissionSet();
    }

    /**
     * 判断当前账号是否拥有指定角色（支持 {@code *} 通配符模糊匹配）。
     *
     * @param role 角色标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasRole(String role) {
        return getFacade().hasRole(role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAllRole(String... roles) {
        return getFacade().hasAllRole(roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAnyRole(String... roles) {
        return getFacade().hasAnyRole(roles);
    }

    /**
     * 判断当前账号是否拥有指定权限（支持 {@code *} 通配符模糊匹配）。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasPermission(String permission) {
        return getFacade().hasPermission(permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAllPermission(String... permissions) {
        return getFacade().hasAllPermission(permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAnyPermission(String... permissions) {
        return getFacade().hasAnyPermission(permissions);
    }
}
