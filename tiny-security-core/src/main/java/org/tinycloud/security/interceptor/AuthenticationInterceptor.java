package org.tinycloud.security.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.tinycloud.security.annotation.AnnotationUtils;
import org.tinycloud.security.authentication.AuthenticationManager;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;

import java.lang.reflect.Method;

/**
 * 用户会话验证拦截器
 *
 * @author liuxingyu01
 * @version 2020-03-22-11:23
 **/
public class AuthenticationInterceptor implements HandlerInterceptor {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    /**
     * 构造会话认证拦截器。
     *
     * @param authenticationManager       认证管理器
     * @param securityContextRepository   安全上下文仓储
     */
    public AuthenticationInterceptor(AuthenticationManager authenticationManager,
                                      SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    /*
     * 进入controller层之前拦截请求
     * 返回值：表示是否将当前的请求拦截下来  false：拦截请求，请求别终止。true：请求不被拦截，继续执行
     * Object obj:表示被拦的请求的目标对象（controller中方法）
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        // 判断请求类型，如果是OPTIONS，直接返回
        String options = HttpMethod.OPTIONS.toString();
        if (options.equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }

        // 检查是否忽略会话验证
        Method method = ((HandlerMethod) handler).getMethod();
        if (AnnotationUtils.checkIgnore(method)) {
            return true;
        }
        SecurityContext context = this.authenticationManager.authenticate(request);
        // 存入安全上下文，以方便后续使用
        this.securityContextRepository.saveContext(context, request, response);
        // 合格不需要拦截，放行
        return true;
    }


    /*
     * 处理请求完成后视图渲染之前的处理操作
     * 通过ModelAndView参数改变显示的视图，或发往视图的方法
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
    }

    /*
     * 视图渲染之后的操作
     */
    @Override
    public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object arg2, Exception arg3) throws Exception {
        this.securityContextRepository.clearContext(arg0, arg1);
    }
}
