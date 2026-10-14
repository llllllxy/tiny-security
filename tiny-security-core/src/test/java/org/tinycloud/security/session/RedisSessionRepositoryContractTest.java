package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * {@link RedisSessionRepository} 的契约测试（TCK 子类），跑在**真实 Redis** 上。
 *
 * <p><b>为什么必须用真实 Redis</b>：{@link RedisSessionRepositoryTest} 是纯 Mockito 的
 * 契约级验证，它无法覆盖 TTL 是否真的设置、Lua 脚本是否真的原子、JSON 序列化往返是否真的成立
 * （TST-6）。而 TCK 里的用例（读写往返、登录并发上限、过期判定）都必须落到真实服务上才有意义 ——
 * 用 Mockito 跑 TCK 等于把"实现是否正确"换成"我是否把 mock 打桩打对了"。
 *
 * <p><b>如何启用</b>：默认**跳过**（CI 环境没有 Redis，且不应把连接信息写进仓库）。
 * 本地要跑时设置环境变量：
 * <pre>
 * TINY_SECURITY_TCK_REDIS=1               # 或直接给测试进程加 -Dtiny.security.tck.redis=true
 * TINY_SECURITY_TCK_REDIS_HOST=127.0.0.1  # 可选，默认 127.0.0.1
 * TINY_SECURITY_TCK_REDIS_PORT=6379       # 可选，默认 6379
 * TINY_SECURITY_TCK_REDIS_PASSWORD=...    # 可选
 * TINY_SECURITY_TCK_REDIS_DATABASE=15     # 可选，默认 15（刻意不用 0，降低误伤业务数据的风险）
 * </pre>
 *
 * <p><b>数据隔离</b>：所有 key 都由仓储按固定前缀生成（{@code tiny:security:credentials:*} /
 * {@code tiny:security:online:*}），本类只清理这些前缀下的 key，**绝不执行 FLUSHDB**。
 *
 * @author liuxingyu01
 */
@EnabledIf("redisTckEnabled")
class RedisSessionRepositoryContractTest extends SessionRepositoryContractTest {

    private LettuceConnectionFactory connectionFactory;
    private StringRedisTemplate redisTemplate;

    /**
     * 是否启用真实 Redis 的 TCK：需显式设置开关（环境变量或系统属性），避免在无 Redis 的环境误跑。
     *
     * @return true 表示启用
     */
    static boolean redisTckEnabled() {
        String flag = System.getProperty("tiny.security.tck.redis");
        if (flag == null || flag.isEmpty()) {
            flag = System.getenv("TINY_SECURITY_TCK_REDIS");
        }
        return "true".equalsIgnoreCase(flag) || "1".equals(flag);
    }

    @BeforeEach
    void setUp() {
        RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration(
                env("TINY_SECURITY_TCK_REDIS_HOST", "tiny.security.tck.redis.host", "127.0.0.1"),
                Integer.parseInt(env("TINY_SECURITY_TCK_REDIS_PORT", "tiny.security.tck.redis.port", "6379")));
        String password = env("TINY_SECURITY_TCK_REDIS_PASSWORD", "tiny.security.tck.redis.password", "");
        if (!password.isEmpty()) {
            configuration.setPassword(password);
        }
        configuration.setDatabase(Integer.parseInt(
                env("TINY_SECURITY_TCK_REDIS_DATABASE", "tiny.security.tck.redis.database", "15")));

        connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
    }

    @AfterEach
    void cleanUp() {
        if (redisTemplate != null) {
            // 只清理本框架自己的 key 前缀，绝不用 FLUSHDB（可能误伤同库的其它业务数据）
            redisTemplate.delete(redisTemplate.keys("tiny:security:credentials:*"));
            redisTemplate.delete(redisTemplate.keys("tiny:security:online:*"));
        }
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Override
    protected SessionRepository createRepository() {
        return new RedisSessionRepository(redisTemplate);
    }

    @Override
    protected void destroyRepository(SessionRepository repository) {
        // Redis 连接由 @AfterEach 统一释放，仓储自身不持有需要关闭的资源
    }

    private static String env(String envName, String propertyName, String defaultValue) {
        String value = System.getProperty(propertyName);
        if (value == null || value.isEmpty()) {
            value = System.getenv(envName);
        }
        return (value == null || value.isEmpty()) ? defaultValue : value;
    }
}
