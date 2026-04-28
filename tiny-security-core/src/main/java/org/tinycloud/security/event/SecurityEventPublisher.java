package org.tinycloud.security.event;

/**
 * 安全事件发布器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface SecurityEventPublisher {

    /**
     * 发布登录成功事件
     *
     * @param event 事件
     */
    void publishLoginSuccess(LoginSuccessEvent event);

    /**
     * 发布登录失败事件
     *
     * @param event 事件
     */
    void publishLoginFailure(LoginFailureEvent event);

    /**
     * 发布鉴权失败事件
     *
     * @param event 事件
     */
    void publishAuthorizationFailure(AuthorizationFailureEvent event);
}
