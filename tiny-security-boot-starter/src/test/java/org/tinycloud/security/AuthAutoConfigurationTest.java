package org.tinycloud.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.CaffeineSessionRepository;
import org.tinycloud.security.session.JdbcSessionRepository;
import org.tinycloud.security.session.RedisSessionRepository;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * AuthAutoConfiguration 自动装配测试。
 *
 * <p>使用 Spring Boot 官方 {@link ApplicationContextRunner} 验证条件装配逻辑
 * （不启动完整 Servlet 容器，无需真实 Redis/JDBC 连接）：
 * <ul>
 *     <li>默认（store-type 缺失）→ 装配单机内存仓储</li>
 *     <li>store-type=redis（且存在 StringRedisTemplate）→ 装配 Redis 仓储</li>
 *     <li>store-type=jdbc（且存在 JdbcTemplate）→ 装配 JDBC 仓储</li>
 *     <li>用户自定义 SessionRepository / AuthProvider → 不被默认 Bean 覆盖</li>
 *     <li>exception-translation-enabled=false → 不注册框架异常解析器</li>
 *     <li>配置属性（token-name 等）正确绑定到 AuthProperties</li>
 * </ul>
 */
class AuthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthAutoConfiguration.class))
            .withPropertyValues("tiny-security.banner=false");

    @Test
    void shouldAssembleSingleRepositoryByDefault() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(SessionRepository.class);
            assertThat(context).hasSingleBean(SingleSessionRepository.class);
            assertThat(context).hasSingleBean(AuthProvider.class);
            assertThat(context).hasSingleBean(TinySecurityFacade.class);
            assertThat(context).hasSingleBean(SecurityContextRepository.class);
            assertThat(context).hasSingleBean(SecurityEventPublisher.class);
            assertThat(context).hasSingleBean(HandlerExceptionResolver.class);
        });
    }

    @Test
    void shouldAssembleRedisRepositoryWhenStoreTypeIsRedis() {
        runner.withUserConfiguration(RedisConfig.class)
                .withPropertyValues("tiny-security.store-type=redis")
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionRepository.class);
                    assertThat(context).hasSingleBean(RedisSessionRepository.class);
                    assertThat(context).doesNotHaveBean(SingleSessionRepository.class);
                });
    }

    @Test
    void shouldAssembleJdbcRepositoryWhenStoreTypeIsJdbc() {
        runner.withUserConfiguration(JdbcConfig.class)
                .withPropertyValues("tiny-security.store-type=jdbc")
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionRepository.class);
                    assertThat(context).hasSingleBean(JdbcSessionRepository.class);
                    assertThat(context).doesNotHaveBean(SingleSessionRepository.class);
                });
    }

    @Test
    void shouldAssembleCaffeineRepositoryWhenStoreTypeIsCaffeine() {
        runner.withPropertyValues("tiny-security.store-type=caffeine")
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionRepository.class);
                    assertThat(context).hasSingleBean(CaffeineSessionRepository.class);
                    assertThat(context).doesNotHaveBean(SingleSessionRepository.class);
                });
    }

    @Test
    void shouldNotOverrideUserDefinedSessionRepository() {
        runner.withUserConfiguration(CustomSessionRepositoryConfig.class)
                .run(context -> {
                    // 用户自定义仓储存在时，默认仓储不创建，且 bean 不是默认的 Single 类型
                    assertThat(context).hasSingleBean(SessionRepository.class);
                    assertThat(context).doesNotHaveBean(SingleSessionRepository.class);
                    SessionRepository bean = context.getBean(SessionRepository.class);
                    assertThat(bean).isInstanceOf(SessionRepository.class);
                });
    }

    @Test
    void shouldNotOverrideUserDefinedAuthProvider() {
        runner.withUserConfiguration(CustomAuthProviderConfig.class)
                .run(context -> assertThat(context).hasSingleBean(AuthProvider.class));
    }

    @Test
    void shouldNotRegisterExceptionResolverWhenDisabled() {
        runner.withPropertyValues("tiny-security.exception-translation-enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(HandlerExceptionResolver.class));
    }

    @Test
    void shouldBindTokenNameProperty() {
        runner.withPropertyValues("tiny-security.token-name=access-token")
                .run(context -> {
                    AuthProperties properties = context.getBean(AuthProperties.class);
                    assertThat(properties.getTokenName()).isEqualTo("access-token");
                });
    }

    @Test
    void shouldBindNewSecurityProperties() {
        runner.withPropertyValues(
                        "tiny-security.enable-url-token=true",
                        "tiny-security.enable-cookie=true",
                        "tiny-security.cookie-secure=true")
                .run(context -> {
                    AuthProperties properties = context.getBean(AuthProperties.class);
                    assertThat(properties.getEnableUrlToken()).isTrue();
                    assertThat(properties.getEnableCookie()).isTrue();
                    assertThat(properties.getCookieSecure()).isTrue();
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class RedisConfig {
        @Bean
        StringRedisTemplate stringRedisTemplate() {
            return mock(StringRedisTemplate.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class JdbcConfig {
        @Bean
        JdbcTemplate jdbcTemplate() {
            return mock(JdbcTemplate.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomSessionRepositoryConfig {
        @Bean
        SessionRepository customSessionRepository() {
            return mock(SessionRepository.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomAuthProviderConfig {
        @Bean
        AuthProvider customAuthProvider(SessionRepository sessionRepository) {
            AuthProperties properties = new AuthProperties();
            properties.setJwtSecret("test-secret");
            return new AuthProvider(sessionRepository, properties, null);
        }
    }
}
