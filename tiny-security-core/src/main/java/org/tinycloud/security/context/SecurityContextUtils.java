package org.tinycloud.security.context;

import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.web.WebRequestUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * 安全上下文工具类。
 *
 * @author liuxingyu01
 * @since 2026-05-26
 */
public final class SecurityContextUtils {

    /**
     * 禁止实例化安全上下文工具类。
     */
    private SecurityContextUtils() {
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     */
    public static SecurityContext getSecurityContext() {
        HttpServletRequest request = WebRequestUtils.getRequest();
        if (request != null && GlobalConfigUtils.getGlobalConfig() != null) {
            SecurityContextRepository repository = GlobalConfigUtils.getGlobalConfig().getSecurityContextRepository();
            if (repository != null) {
                return repository.loadContext(request);
            }
        }
        return null;
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体
     */
    public static LoginSubject getLoginSubject() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getLoginSubject();
    }

    /**
     * 获取当前角色集合。
     *
     * @return 角色集合
     */
    public static Set<String> getRoleSet() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * @return 权限集合
     */
    public static Set<String> getPermissionSet() {
        SecurityContext context = getSecurityContext();
        return context == null ? null : context.getPermissionSet();
    }
}
