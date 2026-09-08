package org.tinycloud.security.context;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
