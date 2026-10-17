package org.tinycloud.security.context;

import org.junit.jupiter.api.Test;
import org.tinycloud.security.util.JsonUtil;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LoginSubjectTest {

    /**
     * toString 输出到日志时不得携带会话凭证，防止日志泄露 token。
     */
    @Test
    void toStringShouldMaskCredentials() {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("super-secret-credentials");

        String text = subject.toString();

        assertFalse(text.contains("super-secret-credentials"));
        assertTrue(text.contains("credentials=****"));
    }

    /**
     * 携带扩展信息/时间字段时脱敏依然生效，且其它可读字段保留（便于排障）。
     */
    @Test
    void toStringShouldMaskCredentialsAndKeepOtherFields() {
        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("ip", "10.0.0.1");
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(10086L);
        subject.setExtraInfo(extraInfo);
        subject.setLoginTime(1700000000000L);
        subject.setLoginExpireTime(1700001800000L);
        subject.setCredentials("another-secret-value");

        String text = subject.toString();

        assertFalse(text.contains("another-secret-value"));
        assertTrue(text.contains("credentials=****"));
        assertTrue(text.contains("loginId=10086"));
        assertTrue(text.contains("ip=10.0.0.1"));
        assertTrue(text.contains("loginExpireTime=1700001800000"));
    }

    /**
     * 回归（滚动发布）：新实例写入的会话带上了旧实例不认识的字段时，旧实例必须仍能反序列化。
     * 修复前 Jackson 默认的 FAIL_ON_UNKNOWN_PROPERTIES 会让 readValue 返回 null，
     * 上层把它当成"会话不存在"→ 所有在线用户被打成 401。
     */
    @Test
    void shouldIgnoreUnknownFieldsWhenDeserializing() {
        String jsonWrittenByNewerInstance = "{\"loginId\":\"user-1\",\"credentials\":\"cred-1\","
                + "\"loginTime\":1759215845000,\"loginExpireTime\":1759217645000,"
                + "\"fieldAddedInFutureVersion\":\"whatever\"}";

        LoginSubject subject = JsonUtil.readValue(jsonWrittenByNewerInstance, LoginSubject.class);

        assertNotNull(subject);
        assertEquals("user-1", subject.getLoginId());
        assertEquals("cred-1", subject.getCredentials());
        assertEquals(1759215845000L, subject.getLoginTime());
    }
}
