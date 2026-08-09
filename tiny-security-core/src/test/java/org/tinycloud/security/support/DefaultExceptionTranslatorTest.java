package org.tinycloud.security.support;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.JsonUtil;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultExceptionTranslatorTest {

    private final DefaultExceptionTranslator exceptionTranslator = new DefaultExceptionTranslator();

    @Test
    void shouldTranslateUnauthorizedToCode401() throws Exception {
        TranslationResult result = translate(new UnAuthorizedException(), "/secure");

        assertEquals(401, result.status);
        assertEquals(AuthConsts.CODE_UNAUTHORIZED, result.body.get("code"));
        assertEquals("未登录或会话已失效！", result.body.get("message"));
        assertEquals("/secure", result.body.get("path"));
    }

    @Test
    void shouldTranslateNoPermissionToCode403() throws Exception {
        TranslationResult result = translate(new NoPermissionException(), "/admin");

        assertEquals(403, result.status);
        assertEquals(AuthConsts.CODE_NO_PERMISSION, result.body.get("code"));
        assertEquals("无权限访问！", result.body.get("message"));
        assertEquals("/admin", result.body.get("path"));
    }

    @Test
    void shouldTranslateConcurrentLimitToCode409() throws Exception {
        TranslationResult result = translate(new ConcurrentLoginOverLimitException(), "/login");

        assertEquals(409, result.status);
        assertEquals(AuthConsts.CODE_CONCURRENT_LOGIN_OVER_LIMIT, result.body.get("code"));
        assertEquals("/login", result.body.get("path"));
    }

    @Test
    void shouldFallbackTo500WhenCodeMissing() throws Exception {
        TranslationResult result = translate(new TinySecurityException("系统异常"), "/x");

        assertEquals(500, result.status);
        assertEquals(AuthConsts.CODE_OTHER_ERROR, result.body.get("code"));
        assertEquals("系统异常", result.body.get("message"));
    }

    @Test
    void shouldReturn200WhenForceHttpStatus200Enabled() throws Exception {
        DefaultExceptionTranslator forced = new DefaultExceptionTranslator(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();

        forced.translate(request, response, new UnAuthorizedException());

        // 状态码被强制为 200，但业务 code 仍为 401
        assertEquals(200, response.getStatus());
        Map<String, Object> body = JsonUtil.readValue(response.getContentAsString(), Map.class);
        assertEquals(AuthConsts.CODE_UNAUTHORIZED, body.get("code"));
    }

    @SuppressWarnings("unchecked")
    private TranslationResult translate(TinySecurityException ex, String uri) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);
        MockHttpServletResponse response = new MockHttpServletResponse();
        exceptionTranslator.translate(request, response, ex);
        Map<String, Object> body = JsonUtil.readValue(response.getContentAsString(), Map.class);
        return new TranslationResult(response.getStatus(), body);
    }

    static class TranslationResult {
        private final int status;
        private final Map<String, Object> body;

        TranslationResult(int status, Map<String, Object> body) {
            this.status = status;
            this.body = body;
        }
    }
}
