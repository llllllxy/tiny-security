package org.tinycloud.security.session.timedcache;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2025-05-09 16:45
 */
public class LocalMapContainerByConcurrentHashMap<V> implements LocalMapContainer<V> {
    private final ConcurrentHashMap<String, V> map = new ConcurrentHashMap<String, V>();

    @Override
    public Object getSource() {
        return map;
    }

    @Override
    public V get(String key) {
        return map.get(key);
    }

    @Override
    public void put(String key, V value) {
        map.put(key, value);
    }

    @Override
    public void remove(String key) {
        map.remove(key);
    }

    @Override
    public Set<String> keySet() {
        return map.keySet();
    }
}
