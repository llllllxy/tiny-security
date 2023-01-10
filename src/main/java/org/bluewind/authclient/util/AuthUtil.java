package org.bluewind.authclient.util;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;

public class AuthUtil {


    /**
     * 获取用户token
     *
     * @return
     */
    public static String getToken(String tokenName) {
        HttpServletRequest request = null;
        try {
            request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            // 从请求中获取token，先从Header里取，取不到的话再从cookie里取（适配前后端分离的模式）
            String token = request.getHeader(tokenName);
            if (StringUtils.isBlank(token)) {
                token = CookieUtil.getCookie(request, tokenName);
            }
            return token;
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * 获取用户token
     *
     * @return
     */
    public static String getToken(HttpServletRequest request, String tokenName) {
        try {
            // 从请求中获取token，先从Header里取，取不到的话再从cookie里取（适配前后端分离的模式）
            String token = request.getHeader(tokenName);
            if (StringUtils.isBlank(token)) {
                token = CookieUtil.getCookie(request, tokenName);
            }
            return token;
        } catch (Exception e) {
            return null;
        }
    }


}
