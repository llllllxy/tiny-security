package org.bluewind.authclient;

import org.bluewind.authclient.interceptor.AuthenticeInterceptor;
import org.bluewind.authclient.interceptor.PermissionInterceptor;
import org.bluewind.authclient.interfaces.PermissionInfoInterface;
import org.bluewind.authclient.provider.AuthProvider;
import org.bluewind.authclient.provider.JdbcAuthProvider;
import org.bluewind.authclient.provider.RedisAuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collection;

@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@ConditionalOnProperty(name = "authclient.enable", havingValue = "true")
public class AuthAutoConfiguration implements ApplicationContextAware {
    final static Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    private ApplicationContext applicationContext;

    @Autowired
    private AuthProperties authProperties;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }


    /**
     * 根据Class<T>获取Bean
     */
    private <T> T getBean(Class<T> clazz) {
        T bean = null;
        Collection<T> beans = applicationContext.getBeansOfType(clazz).values();
        while (beans.iterator().hasNext()) {
            bean = beans.iterator().next();
            if (bean != null) break;
        }
        return bean;
    }


    /**
     * 注入redisAuthStore
     */
    @ConditionalOnMissingBean(AuthProvider.class)
    @ConditionalOnProperty(name = "authclient.store-type", havingValue = "redis")
    @Bean
    public AuthProvider redisAuthProvider() {
        StringRedisTemplate stringRedisTemplate = getBean(StringRedisTemplate.class);
        if (stringRedisTemplate == null) {
            logger.error("AuthAutoConfiguration: StringRedisTemplate is null");
        }
        return new RedisAuthProvider(stringRedisTemplate, authProperties);
    }

    /**
     * 注入jdbcAuthStore
     */
    @ConditionalOnMissingBean(AuthProvider.class)
    @ConditionalOnProperty(name = "authclient.store-type", havingValue = "jdbc")
    @Bean
    public AuthProvider jdbcAuthProvider() {
        JdbcTemplate jdbcTemplate = getBean(JdbcTemplate.class);
        if (jdbcTemplate == null) {
            logger.error("AuthAutoConfiguration: JdbcTemplate is null");
        }
        return new JdbcAuthProvider(jdbcTemplate, authProperties);
    }


    /**
     * 添加会话拦截器
     */
    @Bean
    public AuthenticeInterceptor authenticeInterceptor() {
        // 获取AuthStore（可能是redis的，也可能是jdbc的，根据配置来的）
        AuthProvider authProvider = getBean(AuthProvider.class);
        if (authProvider != null) {
            return new AuthenticeInterceptor(authProvider, authProperties);
        } else {
            logger.error("AuthAutoConfiguration: Unknown AuthStore");
            return null;
        }
    }


    /**
     * 添加权限拦截器（当存在bean PermissionInfoInterface时，这个配置才生效）
     */
    @Bean
    @ConditionalOnBean(PermissionInfoInterface.class)
    public PermissionInterceptor permissionInterceptor() {
        // 获取PermissionInfoInterface
        PermissionInfoInterface permissionInfoInterface = getBean(PermissionInfoInterface.class);
        if (permissionInfoInterface != null) {
            return new PermissionInterceptor(permissionInfoInterface);
        } else {
            logger.error("AuthAutoConfiguration: Unknown PermissionInfoInterface");
            return null;
        }
    }

}
