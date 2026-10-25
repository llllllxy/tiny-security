package org.tinycloud.security.event;

import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SpringSecurityEventPublisher} 的透传契约测试。
 *
 * <p>该类把三类安全事件桥接到 Spring 的事件总线。逻辑很薄，但「漏转发某一种事件」
 * 是典型的静默失败 —— 监听器收不到，日志里也没有任何痕迹。这里把三种事件
 * 逐一锁定。
 *
 * @author liuxingyu01
 */
class SpringSecurityEventPublisherTest {

    /**
     * 三种事件都必须原样转发给 Spring 的 ApplicationEventPublisher。
     */
    @Test
    void shouldForwardAllThreeEventTypes() {
        RecordingEventPublisher spring = new RecordingEventPublisher();
        SpringSecurityEventPublisher publisher = new SpringSecurityEventPublisher(spring);

        LoginSuccessEvent success = new LoginSuccessEvent(1L, "Bearer t", Collections.emptyMap(), 1000L);
        LoginFailureEvent failure = new LoginFailureEvent(2L, Collections.emptyMap(), "reason", 2000L);
        AuthorizationFailureEvent authz =
                new AuthorizationFailureEvent(3L, "/admin", "list", "no permission", 3000L);

        publisher.publishLoginSuccess(success);
        publisher.publishLoginFailure(failure);
        publisher.publishAuthorizationFailure(authz);

        assertEquals(3, spring.published.size(), "三种事件都应被发布");
        assertSame(success, spring.published.get(0), "登录成功事件应原样透传");
        assertSame(failure, spring.published.get(1), "登录失败事件应原样透传");
        assertSame(authz, spring.published.get(2), "鉴权失败事件应原样透传");
    }

    /**
     * 底层发布器抛出的异常应当向上传播，不做吞没 —— 由调用方（AuthProvider）
     * 决定是否隔离。若这里静默吞掉，P1-11 的隔离逻辑就永远走不到。
     */
    @Test
    void shouldPropagateExceptionFromUnderlyingPublisher() {
        ApplicationEventPublisher broken = event -> {
            throw new IllegalStateException("bus down");
        };
        SpringSecurityEventPublisher publisher = new SpringSecurityEventPublisher(broken);

        assertThrows(IllegalStateException.class,
                () -> publisher.publishLoginSuccess(new LoginSuccessEvent(1L, "t", Collections.emptyMap(), 1L)));
    }

    /**
     * 记录所有被发布事件的最小替身。
     */
    static class RecordingEventPublisher implements ApplicationEventPublisher {
        private final List<Object> published = new ArrayList<>();

        @Override
        public void publishEvent(Object event) {
            published.add(event);
        }
    }
}
