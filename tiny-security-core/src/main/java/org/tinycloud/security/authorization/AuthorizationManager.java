package org.tinycloud.security.authorization;

import javax.servlet.http.HttpServletRequest;
import org.tinycloud.security.context.SecurityContext;

import java.lang.reflect.Method;

/**
 * 授权管理器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface AuthorizationManager {

    /**
     * 执行授权
     *
     * @param request 请求对象
     * @param method  目标方法
     * @param context 安全上下文
     * @return 授权结果
     */
    AuthorizationDecision authorize(HttpServletRequest request, Method method, SecurityContext context);
}
