package org.tinycloud.security.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.SessionRepository;

import java.util.Objects;

/**
 * 默认认证管理器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class DefaultAuthenticationManager implements AuthenticationManager {
    private final AuthProvider authProvider;
    private final SessionRepository sessionRepository;
    private final int timeout;

    /**
     * 构造默认认证管理器。
     *
     * @param authProvider      认证外观
     * @param sessionRepository 会话仓储
     * @param timeout           会话超时时间（秒）
     */
    public DefaultAuthenticationManager(AuthProvider authProvider, SessionRepository sessionRepository, int timeout) {
        Assert.notNull(authProvider, "The authProvider cannot be null!");
        Assert.notNull(sessionRepository, "The sessionRepository cannot be null!");
        this.authProvider = authProvider;
        this.sessionRepository = sessionRepository;
        this.timeout = timeout;
    }

    /**
     * 执行请求认证并在必要时刷新会话过期时间。
     *
     * @param request 当前请求
     * @return 安全上下文
     */
    @Override
    public SecurityContext authenticate(HttpServletRequest request) {
        String credentials = this.authProvider.getCredentials(request);
        if (!StringUtils.hasText(credentials)) {
            throw new UnAuthorizedException();
        }

        LoginSubject subject = this.sessionRepository.getSubject(credentials);
        if (Objects.isNull(subject)) {
            throw new UnAuthorizedException();
        }

        long expireTime = subject.getLoginExpireTime();
        long currentTime = System.currentTimeMillis();
        long millsCritical = (long) (this.timeout * 1000L * 0.8);
        if (expireTime - currentTime <= millsCritical) {
            subject.setLoginExpireTime(currentTime + this.timeout * 1000L);
            this.sessionRepository.refreshByCredentials(credentials, subject, this.timeout);
        }
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        return context;
    }
}
