package org.tinycloud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.tinycloud.security.authentication.AuthenticationManager;
import org.tinycloud.security.authentication.DefaultAuthenticationManager;
import org.tinycloud.security.authorization.AuthorizationManager;
import org.tinycloud.security.authorization.DefaultAuthorizationManager;
import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.event.SpringSecurityEventPublisher;
import org.tinycloud.security.interceptor.AuthenticationInterceptor;
import org.tinycloud.security.interceptor.AuthorizationInterceptor;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.JdbcSessionRepository;
import org.tinycloud.security.session.RedisSessionRepository;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;
import org.tinycloud.security.support.DefaultExceptionTranslator;
import org.tinycloud.security.support.ExceptionTranslator;
import org.tinycloud.security.support.TinySecurityHandlerExceptionResolver;
import org.tinycloud.security.util.VersionUtil;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * <p>
 * tiny-security 自动配置类
 * </p>
 *
 * @author liuxingyu01
 * @since 2022-12-13 11:45
 **/
@ConditionalOnClass({HandlerInterceptor.class, WebMvcConfigurer.class})
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration implements WebMvcConfigurer, ApplicationContextAware, ApplicationListener<ContextRefreshedEvent> {
    final static Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    @Autowired
    private AuthProperties authProperties;

    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     * 添加拦截器
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册会话拦截器
        registry.addInterceptor(new AuthenticationInterceptor())
                .addPathPatterns(authProperties.getIncludePath())
                .excludePathPatterns(authProperties.getExcludePath())
                .order(-2);
        // 注册权限拦截器（选择性）
        if (authProperties.getAuthorizationEnabled()) {
            registry.addInterceptor(new AuthorizationInterceptor())
                    .addPathPatterns(authProperties.getIncludePath())
                    .excludePathPatterns(authProperties.getExcludePath())
                    .order(-1);
        }
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        // 避免重复初始化
        if (Objects.nonNull(GlobalConfigUtils.getGlobalConfig())) {
            return;
        }
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setVersion(VersionUtil.getVersion());
        globalConfig.setBanner(authProperties.getBanner());
        globalConfig.setStoreType(authProperties.getStoreType());
        globalConfig.setTableName(authProperties.getTableName());
        globalConfig.setTimeout(authProperties.getTimeout());
        globalConfig.setTokenName(authProperties.getTokenName());
        globalConfig.setCredentialsStyle(authProperties.getCredentialsStyle());
        globalConfig.setPermCheckMode(authProperties.getPermCheckMode());
        globalConfig.setJwtSecret(authProperties.getJwtSecret());
        globalConfig.setJwtSubject(authProperties.getJwtSubject());
        globalConfig.setMaxConcurrentLogins(authProperties.getMaxConcurrentLogins());
        /* 获取自定义的（ID生成器） */

        this.getBeanThen(SessionRepository.class, globalConfig::setSessionRepository);
        this.getBeanThen(AuthProvider.class, globalConfig::setAuthProvider);
        this.getBeanThen(AuthenticationManager.class, globalConfig::setAuthenticationManager);
        this.getBeanThen(AuthorizationManager.class, globalConfig::setAuthorizationManager);
        this.getBeanThen(SecurityContextRepository.class, globalConfig::setSecurityContextRepository);
        this.getBeanThen(SecurityEventPublisher.class, globalConfig::setSecurityEventPublisher);
        /* 获取自定义的（AuthorizationInfoGetInterface */
        this.getBeanThen(AuthorizationInfoGet.class, globalConfig::setAuthorizationInfoGet);
        GlobalConfigUtils.setGlobalConfig(globalConfig);

        if (logger.isInfoEnabled()) {
            logger.info("Tiny-Security started successfully, version: {}.", globalConfig.getVersion());
        }
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "redis")
    @Bean
    /**
     * 注册 Redis 会话仓储。
     *
     * @param stringRedisTemplate Redis 模板
     * @return 会话仓储
     */
    public SessionRepository redisSessionRepository(@Autowired StringRedisTemplate stringRedisTemplate) {
        if (stringRedisTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean StringRedisTemplate is null!");
            return null;
        }
        logger.info("RedisSessionRepository is running!");
        return new RedisSessionRepository(stringRedisTemplate);
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "jdbc")
    @Bean
    /**
     * 注册 JDBC 会话仓储。
     *
     * @param jdbcTemplate JDBC 模板
     * @return 会话仓储
     */
    public SessionRepository jdbcSessionRepository(@Autowired JdbcTemplate jdbcTemplate) {
        if (jdbcTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean JdbcTemplate is null!");
            return null;
        }
        logger.info("JdbcSessionRepository is running!");
        return new JdbcSessionRepository(jdbcTemplate, authProperties.getTableName());
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "single", matchIfMissing = true)
    @Bean
    /**
     * 注册单机内存会话仓储。
     *
     * @return 会话仓储
     */
    public SessionRepository singleSessionRepository() {
        logger.info("SingleSessionRepository is running!");
        return new SingleSessionRepository();
    }

    @Bean
    @ConditionalOnMissingBean(AuthProvider.class)
    /**
     * 注册默认 AuthProvider 外观实现。
     *
     * @param sessionRepository 会话仓储
     * @return AuthProvider
     */
    public AuthProvider authProvider(SessionRepository sessionRepository) {
        return new AuthProvider(sessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    /**
     * 注册默认认证管理器。
     *
     * @param authProvider      AuthProvider 外观
     * @param sessionRepository 会话仓储
     * @return 认证管理器
     */
    public AuthenticationManager authenticationManager(AuthProvider authProvider, SessionRepository sessionRepository) {
        Integer timeout = authProperties.getTimeout();
        return new DefaultAuthenticationManager(authProvider, sessionRepository, timeout == null ? 1800 : timeout);
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationManager.class)
    /**
     * 注册默认授权管理器。
     *
     * @param authorizationInfoGet 授权信息提供器
     * @return 授权管理器
     */
    public AuthorizationManager authorizationManager(@Autowired(required = false) AuthorizationInfoGet authorizationInfoGet) {
        return new DefaultAuthorizationManager(authProperties.getPermCheckMode(), authorizationInfoGet);
    }

    @Bean
    @ConditionalOnMissingBean(ExceptionTranslator.class)
    /**
     * 注册默认异常翻译器。
     *
     * @return 异常翻译器
     */
    public ExceptionTranslator exceptionTranslator() {
        return new DefaultExceptionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextRepository.class)
    /**
     * 注册默认安全上下文仓储。
     *
     * @return 安全上下文仓储
     */
    public SecurityContextRepository securityContextRepository() {
        return new ThreadLocalSecurityContextRepository();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityEventPublisher.class)
    /**
     * 注册基于 Spring 的安全事件发布器。
     *
     * @param applicationEventPublisher Spring 事件发布器
     * @return 安全事件发布器
     */
    public SecurityEventPublisher securityEventPublisher(org.springframework.context.ApplicationEventPublisher applicationEventPublisher) {
        return new SpringSecurityEventPublisher(applicationEventPublisher);
    }

    @Bean
    @ConditionalOnProperty(name = "tiny-security.exception-translation-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(name = "tinySecurityHandlerExceptionResolver")
    /**
     * 注册默认 tiny-security 异常解析器。
     *
     * @param exceptionTranslator 异常翻译器
     * @return 异常解析器
     */
    public HandlerExceptionResolver tinySecurityHandlerExceptionResolver(ExceptionTranslator exceptionTranslator) {
        return new TinySecurityHandlerExceptionResolver(exceptionTranslator);
    }

    /**
     * 根据Class<T>获取Bean
     *
     * @param clazz    Class
     * @param <T>      泛型
     * @param consumer 操作
     */
    public <T> void getBeanThen(Class<T> clazz, Consumer<T> consumer) {
        if (this.applicationContext.getBeanNamesForType(clazz, false, false).length > 0) {
            consumer.accept(this.applicationContext.getBean(clazz));
        }
    }
}
