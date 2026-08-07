package org.tinycloud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
public class AuthAutoConfiguration implements WebMvcConfigurer, ApplicationListener<ContextRefreshedEvent> {
    final static Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    @Autowired
    private AuthProperties authProperties;

    @Autowired
    private ObjectProvider<SessionRepository> sessionRepositoryProvider;

    @Autowired
    private ObjectProvider<AuthProvider> authProviderProvider;

    @Autowired
    private ObjectProvider<AuthenticationManager> authenticationManagerProvider;

    @Autowired
    private ObjectProvider<AuthorizationManager> authorizationManagerProvider;

    @Autowired
    private ObjectProvider<SecurityContextRepository> securityContextRepositoryProvider;

    @Autowired
    private ObjectProvider<SecurityEventPublisher> securityEventPublisherProvider;

    @Autowired
    private ObjectProvider<AuthorizationInfoGet> authorizationInfoGetProvider;

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

        sessionRepositoryProvider.ifAvailable(globalConfig::setSessionRepository);
        authProviderProvider.ifAvailable(globalConfig::setAuthProvider);
        authenticationManagerProvider.ifAvailable(globalConfig::setAuthenticationManager);
        authorizationManagerProvider.ifAvailable(globalConfig::setAuthorizationManager);
        securityContextRepositoryProvider.ifAvailable(globalConfig::setSecurityContextRepository);
        securityEventPublisherProvider.ifAvailable(globalConfig::setSecurityEventPublisher);
        /* 获取自定义的（AuthorizationInfoGetInterface */
        authorizationInfoGetProvider.ifAvailable(globalConfig::setAuthorizationInfoGet);
        GlobalConfigUtils.setGlobalConfig(globalConfig);

        if (logger.isInfoEnabled()) {
            logger.info("Tiny-Security started successfully, version: {}.", globalConfig.getVersion());
        }
    }

    /**
     * 注册 Redis 会话仓储。
     *
     * @param stringRedisTemplate Redis 模板
     * @return 会话仓储
     */
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "redis")
    @ConditionalOnClass(StringRedisTemplate.class)
    @ConditionalOnBean(StringRedisTemplate.class)
    @ConditionalOnMissingBean(SessionRepository.class)
    @Bean
    public SessionRepository redisSessionRepository(@Autowired StringRedisTemplate stringRedisTemplate) {
        if (stringRedisTemplate == null) {
            throw new IllegalStateException("AuthAutoConfiguration: Bean StringRedisTemplate is null!");
        }
        logger.info("RedisSessionRepository is running!");
        return new RedisSessionRepository(stringRedisTemplate);
    }

    /**
     * 注册 JDBC 会话仓储。
     *
     * @param jdbcTemplate JDBC 模板
     * @return 会话仓储
     */
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "jdbc")
    @ConditionalOnClass(JdbcTemplate.class)
    @ConditionalOnBean(JdbcTemplate.class)
    @ConditionalOnMissingBean(SessionRepository.class)
    @Bean
    public SessionRepository jdbcSessionRepository(@Autowired JdbcTemplate jdbcTemplate) {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("AuthAutoConfiguration: Bean JdbcTemplate is null!");
        }
        logger.info("JdbcSessionRepository is running!");
        return new JdbcSessionRepository(jdbcTemplate, authProperties.getTableName());
    }

    /**
     * 注册单机内存会话仓储。
     *
     * @return 会话仓储
     */
    @ConditionalOnMissingBean(SessionRepository.class)
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "single", matchIfMissing = true)
    @Bean
    public SessionRepository singleSessionRepository() {
        logger.info("SingleSessionRepository is running!");
        return new SingleSessionRepository();
    }

    /**
     * 注册默认 AuthProvider 外观实现。
     *
     * @param sessionRepository 会话仓储
     * @return AuthProvider
     */
    @Bean
    @ConditionalOnMissingBean(AuthProvider.class)
    public AuthProvider authProvider(SessionRepository sessionRepository) {
        return new AuthProvider(sessionRepository);
    }

    /**
     * 注册默认认证管理器。
     *
     * @param authProvider      AuthProvider 外观
     * @param sessionRepository 会话仓储
     * @return 认证管理器
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager authenticationManager(AuthProvider authProvider, SessionRepository sessionRepository) {
        Integer timeout = authProperties.getTimeout();
        return new DefaultAuthenticationManager(authProvider, sessionRepository, timeout == null ? 1800 : timeout);
    }

    /**
     * 注册默认授权管理器。
     *
     * @param authorizationInfoGet 授权信息提供器
     * @return 授权管理器
     */
    @Bean
    @ConditionalOnMissingBean(AuthorizationManager.class)
    public AuthorizationManager authorizationManager(@Autowired(required = false) AuthorizationInfoGet authorizationInfoGet) {
        return new DefaultAuthorizationManager(authProperties.getPermCheckMode(), authorizationInfoGet);
    }

    /**
     * 注册默认异常翻译器。
     *
     * @return 异常翻译器
     */
    @Bean
    @ConditionalOnMissingBean(ExceptionTranslator.class)
    public ExceptionTranslator exceptionTranslator() {
        return new DefaultExceptionTranslator(authProperties.getForceHttpStatus200());
    }

    /**
     * 注册默认安全上下文仓储。
     *
     * @return 安全上下文仓储
     */
    @Bean
    @ConditionalOnMissingBean(SecurityContextRepository.class)
    public SecurityContextRepository securityContextRepository() {
        return new ThreadLocalSecurityContextRepository();
    }

    /**
     * 注册基于 Spring 的安全事件发布器。
     *
     * @param applicationEventPublisher Spring 事件发布器
     * @return 安全事件发布器
     */
    @Bean
    @ConditionalOnMissingBean(SecurityEventPublisher.class)
    public SecurityEventPublisher securityEventPublisher(org.springframework.context.ApplicationEventPublisher applicationEventPublisher) {
        return new SpringSecurityEventPublisher(applicationEventPublisher);
    }

    /**
     * 注册默认 tiny-security 异常解析器。
     *
     * @param exceptionTranslator 异常翻译器
     * @return 异常解析器
     */
    @Bean
    @ConditionalOnProperty(name = "tiny-security.exception-translation-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(name = "tinySecurityHandlerExceptionResolver")
    public HandlerExceptionResolver tinySecurityHandlerExceptionResolver(ExceptionTranslator exceptionTranslator) {
        return new TinySecurityHandlerExceptionResolver(exceptionTranslator);
    }

}

