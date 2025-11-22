package org.tinycloud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
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
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.interfaces.PermissionInfoInterface;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.provider.JdbcAuthProvider;
import org.tinycloud.security.provider.RedisAuthProvider;
import org.tinycloud.security.provider.SingleAuthProvider;
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
public class AuthAutoConfiguration implements ApplicationContextAware, ApplicationListener<ContextRefreshedEvent> {
    final static Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    @Autowired
    private AuthProperties authProperties;
    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        // 避免重复初始化
        if (Objects.nonNull(GlobalConfigUtils.getGlobalConfig())) {
            return;
        }
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setVersion(VersionUtil.getVersion());
        globalConfig.setStoreType(authProperties.getStoreType());
        globalConfig.setTableName(authProperties.getTableName());
        globalConfig.setTimeout(authProperties.getTimeout());
        globalConfig.setTokenName(authProperties.getTokenName());
        globalConfig.setCredentialsStyle(authProperties.getCredentialsStyle());
        globalConfig.setPermCheckMode(authProperties.getPermCheckMode());
        globalConfig.setJwtSecret(authProperties.getJwtSecret());
        globalConfig.setJwtSubject(authProperties.getJwtSubject());
        /* 获取自定义的（ID生成器） */
        this.getBeanThen(AuthProvider.class, globalConfig::setAuthProvider);
        /* 获取自定义的（PermissionInfoInterface */
        this.getBeanThen(PermissionInfoInterface.class, globalConfig::setPermissionInfoInterface);
        GlobalConfigUtils.setGlobalConfig(globalConfig);

        if (logger.isInfoEnabled()) {
            logger.info("Tiny-Security started successfully, version: {}.", globalConfig.getVersion());
        }
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "redis")
    @Bean
    public AuthProvider redisAuthProvider(@Autowired StringRedisTemplate stringRedisTemplate) {
        if (stringRedisTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean StringRedisTemplate is null!");
            return null;
        }
        logger.info("RedisAuthProvider is running!");
        return new RedisAuthProvider(stringRedisTemplate);
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "jdbc")
    @Bean
    public AuthProvider jdbcAuthProvider(@Autowired JdbcTemplate jdbcTemplate) {
        if (jdbcTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean JdbcTemplate is null!");
            return null;
        }
        logger.info("JdbcAuthProvider is running!");
        return new JdbcAuthProvider(jdbcTemplate);
    }

    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "single", matchIfMissing = true)
    @Bean
    public AuthProvider singleAuthProvider() {
        logger.info("SingleAuthProvider is running!");
        return new SingleAuthProvider();
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