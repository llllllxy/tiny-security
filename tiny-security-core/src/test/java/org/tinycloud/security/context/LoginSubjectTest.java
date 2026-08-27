package org.tinycloud.security.context;

import org.junit.jupiter.api.Test;

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
}
