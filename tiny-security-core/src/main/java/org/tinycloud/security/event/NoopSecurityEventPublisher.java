package org.tinycloud.security.event;

/**
 * 默认空实现，避免调用方判空
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class NoopSecurityEventPublisher implements SecurityEventPublisher {
    /**
     * 空实现：忽略登录成功事件。
     *
     * @param event 登录成功事件
     */
    @Override
    public void publishLoginSuccess(LoginSuccessEvent event) {
    }

    /**
     * 空实现：忽略登录失败事件。
     *
     * @param event 登录失败事件
     */
    @Override
    public void publishLoginFailure(LoginFailureEvent event) {
    }

    /**
     * 空实现：忽略鉴权失败事件。
     *
     * @param event 鉴权失败事件
     */
    @Override
    public void publishAuthorizationFailure(AuthorizationFailureEvent event) {
    }
}
