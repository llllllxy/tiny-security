package org.tinycloud.security.event;

import org.springframework.context.ApplicationEventPublisher;

/**
 * 基于 Spring 的安全事件发布器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class SpringSecurityEventPublisher implements SecurityEventPublisher {
    private final ApplicationEventPublisher applicationEventPublisher;

    /**
     * 构造 Spring 事件发布器。
     *
     * @param applicationEventPublisher Spring 事件发布器
     */
    public SpringSecurityEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    /**
     * 发布登录成功事件。
     *
     * @param event 登录成功事件
     */
    @Override
    public void publishLoginSuccess(LoginSuccessEvent event) {
        applicationEventPublisher.publishEvent(event);
    }

    /**
     * 发布登录失败事件。
     *
     * @param event 登录失败事件
     */
    @Override
    public void publishLoginFailure(LoginFailureEvent event) {
        applicationEventPublisher.publishEvent(event);
    }

    /**
     * 发布鉴权失败事件。
     *
     * @param event 鉴权失败事件
     */
    @Override
    public void publishAuthorizationFailure(AuthorizationFailureEvent event) {
        applicationEventPublisher.publishEvent(event);
    }
}
