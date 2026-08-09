package org.tinycloud.security.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.tinycloud.security.exception.TinySecurityException;

/**
 * 将 tiny-security 相关异常统一翻译为 HTTP 响应。
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class TinySecurityHandlerExceptionResolver implements HandlerExceptionResolver, Ordered {

    private final ExceptionTranslator exceptionTranslator;

    /**
     * 构造 tiny-security 异常解析器。
     *
     * @param exceptionTranslator 异常翻译器
     */
    public TinySecurityHandlerExceptionResolver(ExceptionTranslator exceptionTranslator) {
        this.exceptionTranslator = exceptionTranslator;
    }

    /**
     * 处理 tiny-security 体系异常。
     *
     * @param request  当前请求
     * @param response 当前响应
     * @param handler  目标处理器
     * @param ex       异常
     * @return 已处理时返回空 ModelAndView，未处理返回 null
     */
    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (!(ex instanceof TinySecurityException)) {
            return null;
        }
        this.exceptionTranslator.translate(request, response, ex);
        return new ModelAndView();
    }

    /**
     * 设置较高优先级，尽早处理安全异常。
     *
     * @return 顺序值
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
