package org.tinycloud.security.provider.timedcache;

import java.util.Set;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2025-05-09 16:43
 */
public interface LocalMapContainer<V> {
    /**
     * 获取底层被包装的源对象
     *
     * @return /
     */
    Object getSource();


    /**
     * 读
     *
     * @param key /
     * @return /
     */
    V get(String key);

    /**
     * 写
     *
     * @param key /
     * @param value /
     */
    void put(String key, V value);

    /**
     * 删
     * @param key /
     */
    void remove(String key);

    /**
     * 所有 key
     */
    Set<String> keySet();
}
