package org.tinycloud.security.support;

import org.junit.jupiter.api.Test;
import org.springframework.core.Ordered;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.ModelAndView;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link TinySecurityHandlerExceptionResolver} 的回归测试。
 *
 * <p>该类是「安全异常 → HTTP 响应」的唯一入口，此前没有任何直接测试。它有两个
 * 关键契约值得锁定：
 * <ol>
 *     <li><b>只接管安全异常</b>：非 {@link TinySecurityException} 必须返回 {@code null}
 *         交还 Spring —— 若误吞，业务异常将不再由业务侧的 {@code @ControllerAdvice} 处理；</li>
 *     <li><b>优先级可配</b>：默认最高优先级，但允许调低以便业务侧优先处理。</li>
 * </ol>
 *
 * @author liuxingyu01
 */
class TinySecurityHandlerExceptionResolverTest {

    private final TinySecurityHandlerExceptionResolver resolver =
            new TinySecurityHandlerExceptionResolver(new DefaultExceptionTranslator());

    /**
     * 安全异常应被接管：返回非 null 的 ModelAndView，且响应已由翻译器写好。
     */
    @Test
    void shouldResolveSecurityException() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        ModelAndView mv = resolver.resolveException(request(), response, null, new UnAuthorizedException());

        assertNotNull(mv, "安全异常必须被本解析器处理");
        assertNull(mv.getViewName(), "已直接写出 JSON，不应渲染视图");
        assertEquals(401, response.getStatus(), "翻译器应已设好状态码");
    }

    /**
     * 其他安全异常同样被接管（这里用 403 验证，而非只靠 401）。
     */
    @Test
    void shouldResolveAnyTinySecurityExceptionSubtype() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        ModelAndView mv = resolver.resolveException(request(), response, null, new NoPermissionException());

        assertNotNull(mv);
        assertEquals(403, response.getStatus());
    }

    /**
     * 非安全异常必须交还 Spring：返回 null，且不得改动响应。
     */
    @Test
    void shouldReturnNullForNonSecurityException() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        ModelAndView mv = resolver.resolveException(request(), response, null,
                new IllegalStateException("业务异常"));

        assertNull(mv, "非安全异常必须返回 null，交给后续解析器");
        assertEquals(200, response.getStatus(), "不应改动响应状态");
        assertEquals("", response.getContentAsString(), "不应写出任何响应体");
    }

    /**
     * 异常的根因是安全异常、但本身不是时，同样不接管 —— 本解析器只认异常本身类型。
     * 这条锁定了「不做 cause 上溯」这一有意选择：cause 上溯会把被业务包装过的
     * 安全异常也抢走，反而破坏业务的处理链。
     */
    @Test
    void shouldNotResolveWhenOnlyCauseIsSecurityException() {
        Exception wrapped = new RuntimeException(new UnAuthorizedException());

        assertNull(resolver.resolveException(request(), new MockHttpServletResponse(), null, wrapped));
    }

    /**
     * 默认优先级为最高，确保安全异常先于业务侧 @ControllerAdvice 处理。
     */
    @Test
    void shouldDefaultToHighestPrecedence() {
        assertEquals(Ordered.HIGHEST_PRECEDENCE, resolver.getOrder());
    }

    /**
     * 可配置优先级：设为 0 时，业务侧 @ControllerAdvice 可以优先处理。
     */
    @Test
    void shouldHonorConfiguredOrder() {
        assertEquals(0, new TinySecurityHandlerExceptionResolver(new DefaultExceptionTranslator(), 0).getOrder());
        assertEquals(Ordered.LOWEST_PRECEDENCE,
                new TinySecurityHandlerExceptionResolver(new DefaultExceptionTranslator(),
                        Ordered.LOWEST_PRECEDENCE).getOrder());
    }

    /**
     * 基类异常（非具体子类）也会被接管 —— 兜底 500。
     */
    @Test
    void shouldResolveBaseTinySecurityException() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        ModelAndView mv = resolver.resolveException(request(), response, null, new TinySecurityException("boom"));

        assertNotNull(mv);
        assertEquals(500, response.getStatus());
    }

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest("GET", "/secure");
    }
}
