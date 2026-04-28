package org.tinycloud.security.support;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultExceptionTranslatorTest {

    private final DefaultExceptionTranslator exceptionTranslator = new DefaultExceptionTranslator();

    @Test
    void shouldTranslateUnauthorizedToCode401() {
        Map<String, Object> body = translate(new UnAuthorizedException(), "/secure");

        assertEquals(401, body.get("code"));
        assertEquals("未登录或会话已失效！", body.get("message"));
        assertEquals("/secure", body.get("path"));
    }

    @Test
    void shouldTranslateNoPermissionToCode403() {
        Map<String, Object> body = translate(new NoPermissionException(), "/admin");

        assertEquals(403, body.get("code"));
        assertEquals("无权限访问！", body.get("message"));
        assertEquals("/admin", body.get("path"));
    }

    @Test
    void shouldTranslateConcurrentLimitToCode409() {
        Map<String, Object> body = translate(new ConcurrentLoginOverLimitException(), "/login");

        assertEquals(409, body.get("code"));
        assertEquals("/login", body.get("path"));
    }

    @Test
    void shouldFallbackTo500WhenCodeMissing() {
        Map<String, Object> body = translate(new TinySecurityException("系统异常"), "/x");

        assertEquals(500, body.get("code"));
        assertEquals("系统异常", body.get("message"));
    }

    private Map<String, Object> translate(TinySecurityException ex, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);
        return exceptionTranslator.translate(request, ex);
    }
}
