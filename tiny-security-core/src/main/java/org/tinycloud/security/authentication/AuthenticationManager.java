package org.tinycloud.security.authentication;

import javax.servlet.http.HttpServletRequest;
import org.tinycloud.security.context.SecurityContext;

/**
 * 认证管理器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface AuthenticationManager {

    /**
     * 执行认证
     *
     * @param request 请求对象
     * @return 安全上下文
     */
    SecurityContext authenticate(HttpServletRequest request);
}
