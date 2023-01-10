package org.bluewind.authclient.interceptor;

import org.apache.commons.lang3.StringUtils;
import org.bluewind.authclient.AuthProperties;
import org.bluewind.authclient.exception.UnAuthorizedException;
import org.bluewind.authclient.provider.AuthStore;
import org.bluewind.authclient.util.AuthUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * 用户会话验证拦截器
 *
 * @author liuxingyu01
 * @version  2020-03-22-11:23
 **/
public class AuthenticeInterceptor extends HandlerInterceptorAdapter {
    final static Logger logger = LoggerFactory.getLogger(AuthenticeInterceptor.class);

    /**
     * 存储会话的接口
     */
    private AuthStore authStore;

    /**
     * 配置文件
     */
    private AuthProperties authProperties;

    public AuthStore getAuthStore() {
        return this.authStore;
    }

    public void setAuthStore(AuthStore authStore) {
        this.authStore = authStore;
    }

    public AuthProperties getAuthProperties() {
        return this.authProperties;
    }

    public void setAuthProperties(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    public AuthenticeInterceptor(AuthStore authStore, AuthProperties authProperties) {
        setAuthStore(authStore);
        setAuthProperties(authProperties);
    }


    /*
     * 进入controller层之前拦截请求
     * 返回值：表示是否将当前的请求拦截下来  false：拦截请求，请求别终止。true：请求不被拦截，继续执行
     * Object obj:表示被拦的请求的目标对象（controller中方法）
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 判断请求类型，如果是OPTIONS，直接返回
        String options = HttpMethod.OPTIONS.toString();
        if (options.equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }
        // 先判断token是否为空
        String token = AuthUtil.getToken(request, this.authProperties.getTokenName());
        if (logger.isInfoEnabled()) {
            logger.info("AuthenticeInterceptor -- preHandle -- token = {}", token);
        }
        if (StringUtils.isBlank(token)) {
            // 直接抛出异常的话，就不需要return false了
            throw new UnAuthorizedException();
        }
        // 再判断token是否存在，存在的话则刷新会话时长
        if (!authStore.checkToken(token)) {
            throw new UnAuthorizedException();
        } else {
            authStore.refreshToken(token);
            // 合格不需要拦截，放行
            return true;
        }
    }


    /*
     * 处理请求完成后视图渲染之前的处理操作
     * 通过ModelAndView参数改变显示的视图，或发往视图的方法
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
        //logger.info("TenantAuthenticeInterceptor -- postHandle -- 执行了");
    }

    /*
     * 视图渲染之后的操作
     */
    @Override
    public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object arg2, Exception arg3) throws Exception {
        //logger.info("TenantAuthenticeInterceptor -- afterCompletion -- 执行了");
    }
}
