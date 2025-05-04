package org.tinycloud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;


import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.interceptor.AuthenticeInterceptor;
import org.tinycloud.security.interceptor.PermissionInterceptor;
import org.tinycloud.security.interfaces.PermissionInfoInterface;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.provider.JdbcAuthProvider;
import org.tinycloud.security.provider.RedisAuthProvider;
import org.tinycloud.security.provider.SingleAuthProvider;
import org.tinycloud.security.util.VersionUtil;

import java.util.Collection;

/**
 * <p>
 * tiny-security 自动配置类
 * </p>
 *
 * @author liuxingyu01
 * @since 2022-12-13 11:45
 **/
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration implements ApplicationContextAware {
    final static Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    @Autowired
    private AuthProperties authProperties;
    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     * 注入redisAuthProvider
     */
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "redis")
    @Bean
    public AuthProvider redisAuthProvider() {
        org.springframework.data.redis.core.StringRedisTemplate stringRedisTemplate = getBean(org.springframework.data.redis.core.StringRedisTemplate.class);
        if (stringRedisTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean StringRedisTemplate is null!");
            return null;
        }
        logger.info("RedisAuthProvider is running!");
        this.setGlobalConfig(authProperties);
        return new RedisAuthProvider(stringRedisTemplate);
    }

    /**
     * 注入jdbcAuthProvider
     */
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "jdbc")
    @Bean
    public AuthProvider jdbcAuthProvider() {
        org.springframework.jdbc.core.JdbcTemplate jdbcTemplate = getBean(org.springframework.jdbc.core.JdbcTemplate.class);
        if (jdbcTemplate == null) {
            logger.error("AuthAutoConfiguration: Bean JdbcTemplate is null!");
            return null;
        }
        logger.info("JdbcAuthProvider is running!");
        this.setGlobalConfig(authProperties);
        return new JdbcAuthProvider(jdbcTemplate);
    }

    /**
     * 注入singleAuthProvider
     */
    @ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "single", matchIfMissing = true)
    @Bean
    public AuthProvider singleAuthProvider() {
        logger.info("SingleAuthProvider is running!");
        this.setGlobalConfig(authProperties);
        return new SingleAuthProvider();
    }


    /**
     * 添加会话拦截器( 注入AuthStore（可能是redis的，也可能是jdbc的，根据配置来的）)
     */
    @Bean
    public AuthenticeInterceptor authenticeInterceptor(@Autowired AuthProvider authProvider) {
        if (authProvider != null) {
            return new AuthenticeInterceptor(authProvider);
        } else {
            logger.error("AuthAutoConfiguration: Bean AuthProvider Not Defined!");
            return null;
        }
    }


    /**
     * 添加权限拦截器（当存在bean PermissionInfoInterface时，这个配置才生效）
     * 注入PermissionInfoInterface
     */
    @ConditionalOnBean(PermissionInfoInterface.class)
    @Bean
    public PermissionInterceptor permissionInterceptor(@Autowired PermissionInfoInterface permissionInfoInterface) {
        if (permissionInfoInterface != null) {
            return new PermissionInterceptor(permissionInfoInterface);
        } else {
            logger.error("AuthAutoConfiguration: Bean PermissionInfoInterface Not Defined!");
            return null;
        }
    }

    private void setGlobalConfig(AuthProperties authProperties) {
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setVersion(VersionUtil.getVersion());
        globalConfig.setStoreType(authProperties.getStoreType());
        globalConfig.setTableName(authProperties.getTableName());
        globalConfig.setTimeout(authProperties.getTimeout());
        globalConfig.setTokenName(authProperties.getTokenName());
        globalConfig.setTokenPrefix(authProperties.getTokenPrefix());
        globalConfig.setTokenStyle(authProperties.getTokenStyle());
        globalConfig.setJwtSecret(authProperties.getJwtSecret());
        globalConfig.setJwtSubject(authProperties.getJwtSubject());
        GlobalConfigUtils.setGlobalConfig(globalConfig);
    }

    /**
     * 获取Bean
     */
    private <T> T getBean(Class<T> clazz) {
        T bean = null;
        Collection<T> beans = applicationContext.getBeansOfType(clazz).values();
        while (beans.iterator().hasNext()) {
            bean = beans.iterator().next();
            if (bean != null) {
                break;
            }
        }
        return bean;
    }
}
