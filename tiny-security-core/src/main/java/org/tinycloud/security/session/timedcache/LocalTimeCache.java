package org.tinycloud.security.session.timedcache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinycloud.security.util.CommonUtil;

import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2025-05-09 16:46
 */
public class LocalTimeCache {
    private final static Logger log = LoggerFactory.getLogger(LocalTimeCache.class);

    /**
     * 常量，每次清理过期数据间隔的时间 (单位: 秒) ，默认值30秒
     */
    public final static int DATA_REFRESH_PERIOD = 30;

    /** 常量，表示一个 key 永不过期 （在一个 key 被标注为永远不过期时返回此值） */
    public final static long NEVER_EXPIRE = -1L;

    /**
     * 常量，表示系统中不存在这个缓存 (在对不存在的key获取剩余存活时间时返回此值)
     */
    public final static long NOT_VALUE_EXPIRE = -2L;

    /**
     * 存储数据的集合
     */
    public LocalMapContainer<Object> dataMap;

    /**
     * 存储数据过期时间的集合（单位: 毫秒）, 记录所有 key 的到期时间 （注意存储的是到期时间，不是剩余存活时间）
     */
    public LocalMapContainer<Long> expireMap;

    public LocalTimeCache(LocalMapContainer<Object> dataMap, LocalMapContainer<Long> expireMap) {
        this.dataMap = dataMap;
        this.expireMap = expireMap;
    }


    // ------------------------ Object 读写操作 ------------------------ //

    /**
     * 从缓存中获取数据（Object）
     *
     * @param key 键
     * @return 值
     */
    public Object getObject(String key) {
        clearKeyByTimeout(key);
        return dataMap.get(key);
    }

    /**
     * 往缓存中存入数据（Object）
     *
     * @param key     键
     * @param object  值
     * @param timeout 有效时间（秒）
     */
    public void setObject(String key, Object object, long timeout) {
        if (timeout == 0 || timeout < NOT_VALUE_EXPIRE) {
            return;
        }
        dataMap.put(key, object);
        expireMap.put(key, timeout == NEVER_EXPIRE ? NEVER_EXPIRE : System.currentTimeMillis() + timeout * 1000);
    }

    /**
     * 更新缓存数据（Object）
     *
     * @param key    键
     * @param object 值
     */
    public void updateObject(String key, Object object) {
        if (getKeyTimeout(key) == NOT_VALUE_EXPIRE) {
            return;
        }
        dataMap.put(key, object);
    }

    /**
     * 删除缓存
     *
     * @param key 键
     */
    public void deleteObject(String key) {
        dataMap.remove(key);
        expireMap.remove(key);
    }

    /**
     * 获取缓存剩余存活时间 (单位：秒)
     *
     * @param key 键
     * @return 剩余存活时间 (单位：秒)
     */
    public long getObjectTimeout(String key) {
        return getKeyTimeout(key);
    }

    /**
     * 更新缓存剩余存活时间 (单位：秒)
     *
     * @param key     键
     * @param timeout 有效时间（秒）
     */
    public void updateObjectTimeout(String key, long timeout) {
        expireMap.put(key, timeout == NEVER_EXPIRE ? NEVER_EXPIRE : System.currentTimeMillis() + timeout * 1000);
    }

    public Set<String> dataMapKeySet() {
        return dataMap.keySet();
    }

    public Set<String> expireMapKeySet() {
        return expireMap.keySet();
    }

    // ------------------------ 过期时间相关操作开始 ------------------------ //

    /**
     * 如果指定key已经过期，则立即清除它
     *
     * @param key 键
     */
    private void clearKeyByTimeout(String key) {
        Long expirationTime = expireMap.get(key);
        // 清除条件：数据存在 && 不是[永不过期] && 已经超过过期时间
        if (expirationTime != null && expirationTime != NEVER_EXPIRE && expirationTime < System.currentTimeMillis()) {
            dataMap.remove(key);
            expireMap.remove(key);
        }
    }

    /**
     * 获取指定key的剩余存活时间 (单位：秒)
     *
     * @param key 键
     */
    private long getKeyTimeout(String key) {
        // 先检查是否已经过期（惰性扫描）
        clearKeyByTimeout(key);
        // 获取过期时间
        Long expire = expireMap.get(key);
        // 如果根本没有这个值，则直接返回NOT_VALUE_EXPIRE
        if (expire == null) {
            return NOT_VALUE_EXPIRE;
        }
        // 计算剩余时间并返回
        long timeout = (expire - System.currentTimeMillis()) / 1000;
        // 小于零时，视为不存在，返回NOT_VALUE_EXPIRE
        if (timeout < 0) {
            dataMap.remove(key);
            expireMap.remove(key);
            return NOT_VALUE_EXPIRE;
        }
        return timeout;
    }


    /**
     * 清理所有已经过期的key
     */
    public void refreshDataMap() {
        for (String key : expireMap.keySet()) {
            clearKeyByTimeout(key);
        }
    }


// ------------------------ 定时清理过期数据 ------------------------ //
    /**
     * 用于定时执行数据清理的线程池
     */
    private volatile ScheduledExecutorService executorService;

    /**
     * 初始化定时任务
     */
    public void initRefreshThread() {
        // 双重校验构造一个单例的ScheduledThreadPool
        if (this.executorService == null) {
            synchronized (LocalTimeCache.class) {
                if (this.executorService == null) {
                    this.executorService = Executors.newScheduledThreadPool(1);
                    this.executorService.scheduleWithFixedDelay(() -> {
                        log.info("LocalTimeCache - refresh - at ：{}", CommonUtil.getCurrentTime());
                        try {
                            // 执行清理方法
                            refreshDataMap();
                        } catch (Exception e2) {
                            log.error("LocalTimeCache - refresh - Exception：{e2}", e2);
                        }
                    }, 10/*首次延迟多长时间后执行*/, DATA_REFRESH_PERIOD/*间隔时间*/, TimeUnit.SECONDS);
                }
            }
        }
        log.info("LocalTimeCache - refresh - init successful!");
    }

    /**
     * 结束定时任务并停止调度线程。
     */
    public void endRefreshThread() {
        ScheduledExecutorService executor = this.executorService;
        if (executor != null) {
            executor.shutdownNow();
        }
    }
}
