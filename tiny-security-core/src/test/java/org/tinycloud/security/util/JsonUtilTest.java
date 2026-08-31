package org.tinycloud.security.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.exception.TinySecurityException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JsonUtil 测试。
 *
 * <p>核心回归点（1.3.3）：writeValueAsString 序列化失败时必须抛 {@link TinySecurityException}，
 * 不再静默返回空串——否则会话仓储会把空串写入 Redis/DB，造成"登录成功但立即 401"的隐蔽故障。</p>
 */
class JsonUtilTest {

    @Test
    void shouldSerializeSimpleMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("loginId", "user-1");
        map.put("active", true);

        String json = JsonUtil.writeValueAsString(map);

        assertTrue(json.contains("\"loginId\":\"user-1\""));
        assertTrue(json.contains("\"active\":true"));
    }

    @Test
    void shouldSerializeNullToEmptyString() {
        assertEquals("", JsonUtil.writeValueAsString(null));
    }

    /**
     * 序列化失败（循环引用触发 Jackson JsonMappingException）必须显式抛错，而非返回空串。
     */
    @Test
    void shouldThrowTinySecurityExceptionWhenSerializationFails() {
        LoopObject loop = new LoopObject();
        loop.self = loop; // 循环引用，Jackson 无法序列化

        TinySecurityException ex = assertThrows(TinySecurityException.class,
                () -> JsonUtil.writeValueAsString(loop));
        assertTrue(ex.getMessage() != null && !ex.getMessage().isEmpty());
    }

    @Test
    void shouldDeserializeObject() {
        String json = "{\"loginId\":\"user-1\",\"active\":true}";

        Map<String, Object> result = JsonUtil.readValue(json, new TypeReference<Map<String, Object>>() {
        });

        assertEquals("user-1", result.get("loginId"));
        assertEquals(true, result.get("active"));
    }

    @Test
    void shouldReturnNullWhenDeserializingEmptyString() {
        assertNull(JsonUtil.readValue("", String.class));
        assertNull(JsonUtil.readValue("   ", String.class));
        // null 需显式转型为 String，消除与 InputStream 重载的歧义
        assertNull(JsonUtil.readValue((String) null, String.class));
    }

    @Test
    void shouldDeserializeList() {
        List<String> list = new ArrayList<>();
        list.add("a");
        list.add("b");
        String json = JsonUtil.writeValueAsString(list);

        List<String> result = JsonUtil.readArrayValue(json, String.class);

        assertEquals(2, result.size());
        assertEquals("a", result.get(0));
        assertEquals("b", result.get(1));
    }

    /**
     * 自引用对象，用于触发 Jackson 序列化失败。
     */
    static class LoopObject {
        public LoopObject self;
    }
}
