package org.tinycloud.security.util;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.web.WebRequestUtils;

import java.util.Set;

/**
 * 常用对外会话便捷工具类（静态便捷外观）。
 *
 * <p><b>1.5.0 起不再依赖任何可变静态全局变量。</b>此前本类持有一个由 {@code AuthAutoConfiguration}
 * 在 {@code @ConditionalOnMissingBean(TinySecurityFacade.class)} 的 Bean 方法里赋值的静态门面，
 * 用户一旦自定义该 Bean，赋值就永远不会发生，本类全部方法随之失效。现在改为每次调用时
 * 从「当前请求的 WebApplicationContext」解析出 {@link AuthProvider}（框架唯一的实例门面）：
 *
 * <pre>
 * 当前请求 → ServletContext → WebApplicationContext → getBean(AuthProvider.class)
 * </pre>
 *
 * <p>因此用户自定义 {@code AuthProvider} / {@code SecurityContextRepository} /
 * {@code AuthorizationInfoGet} 都不会影响本类 —— 容器里放的是谁，本类就用谁。
 *
 * <p><b>限制</b>：本类只适用于「持有当前请求的线程」（即 Web 请求线程）。非 Web 线程
 * （{@code @Async}、MQ 消费线程等）取不到请求，会抛 {@link UnAuthorizedException}；这与 1.5.0
 * 之前的行为一致，异步上下文传播是待办事项。这类场景请直接注入 {@link AuthProvider}。
 *
 * <p><b>1.4.0 行为统一</b>：所有 {@code get*} 与 {@code has*} 方法在未登录/会话失效时统一抛
 * {@link UnAuthorizedException}（不再返回 null），与 {@code AuthProvider} 语义对齐。
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class AuthUtil {

    private AuthUtil() {
    }

    /**
     * 解析当前请求生效的 {@link AuthProvider}。
     *
     * @return 框架唯一实例门面
     * @throws UnAuthorizedException 当前线程没有请求上下文时（非 Web 线程）
     * @throws IllegalStateException 取到了请求，但其中没有可用的 Spring 容器或 AuthProvider Bean（配置错误）
     */
    private static AuthProvider resolveProvider() {
        HttpServletRequest request = WebRequestUtils.getRequest();
        if (request == null) {
            // 非 Web 线程（@Async / MQ 消费线程等）走这里，语义等同于「没有当前上下文」
            throw new UnAuthorizedException();
        }
        ServletContext servletContext = request.getServletContext();
        // 用 findWebApplicationContext 而非 getWebApplicationContext：前者在 ServletContext 的 ROOT 属性
        // 取不到容器时会继续扫描全部属性，从而兼容「Bean 注册在 DispatcherServlet 子容器里」的经典
        // Spring MVC 部署；在 Spring Boot（ROOT 属性即应用容器）下两者行为完全一致。
        WebApplicationContext applicationContext = servletContext == null
                ? null : WebApplicationContextUtils.findWebApplicationContext(servletContext);
        if (applicationContext == null) {
            throw new IllegalStateException("No WebApplicationContext found for the current request. " +
                    "Please ensure tiny-security is properly configured.");
        }
        try {
            return applicationContext.getBean(AuthProvider.class);
        } catch (NoUniqueBeanDefinitionException e) {
            // NoUniqueBeanDefinitionException 是 NoSuchBeanDefinitionException 的子类，必须先捕获，
            // 否则「有多个候选」会被误报成「一个都没有」，把排查方向带反
            throw new IllegalStateException("Multiple AuthProvider beans found in the application context. " +
                    "Please keep only one, or mark one of them as @Primary.", e);
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalStateException("No AuthProvider bean found in the application context. " +
                    "Please ensure tiny-security is properly configured.", e);
        }
    }

    /**
     * 获取当前登录账号ID。
     *
     * @return 登录账号ID（Number 或 String，由登录时传入的 loginId 决定）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Object getLoginId() {
        return resolveProvider().getLoginId();
    }

    /**
     * 获取当前登录账号ID（字符串形式）。
     *
     * @return 字符串账号ID
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static String getLoginIdAsString() {
        return resolveProvider().getLoginIdAsString();
    }

    /**
     * 获取当前登录账号ID（整数形式）。
     *
     * @return 整数账号ID
     * @throws UnAuthorizedException         未登录或会话失效时
     * @throws org.tinycloud.security.exception.TinySecurityException loginId 非数字时
     */
    public static Integer getLoginIdAsInt() {
        return resolveProvider().getLoginIdAsInt();
    }

    /**
     * 获取当前登录账号ID（长整型形式）。
     *
     * @return 长整型账号ID
     * @throws UnAuthorizedException         未登录或会话失效时
     * @throws org.tinycloud.security.exception.TinySecurityException loginId 非数字时
     */
    public static Long getLoginIdAsLong() {
        return resolveProvider().getLoginIdAsLong();
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static SecurityContext getSecurityContext() {
        return resolveProvider().getSecurityContext();
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体（含 loginId、凭证、扩展信息等）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static LoginSubject getLoginSubject() {
        return resolveProvider().getLoginSubject();
    }

    /**
     * 获取当前角色集合。
     *
     * @return 角色集合（可能为空集合）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Set<String> getRoleSet() {
        return resolveProvider().getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * @return 权限集合（可能为空集合）
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static Set<String> getPermissionSet() {
        return resolveProvider().getPermissionSet();
    }

    /**
     * 判断当前账号是否拥有指定角色（支持 {@code *} 通配符模糊匹配）。
     *
     * @param role 角色标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasRole(String role) {
        return resolveProvider().hasRole(role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAllRole(String... roles) {
        return resolveProvider().hasAllRole(roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAnyRole(String... roles) {
        return resolveProvider().hasAnyRole(roles);
    }

    /**
     * 判断当前账号是否拥有指定权限（支持 {@code *} 通配符模糊匹配）。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasPermission(String permission) {
        return resolveProvider().hasPermission(permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAllPermission(String... permissions) {
        return resolveProvider().hasAllPermission(permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     * @throws UnAuthorizedException 未登录或会话失效时
     */
    public static boolean hasAnyPermission(String... permissions) {
        return resolveProvider().hasAnyPermission(permissions);
    }
}
