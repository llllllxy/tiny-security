package org.tinycloud.security.interceptor.holder;

import org.tinycloud.security.provider.LoginSubject;

import java.util.Objects;

/**
 * 本地线程变量-缓存用户会话信息
 *
 * @author liuxingyu01
 * @version 2022-06-14 13:58
 **/
public class AuthenticeHolder {
    private final static ThreadLocal<LoginSubject> authentice = new ThreadLocal<>();

    public static LoginSubject getLoginSubject() {
        LoginSubject subject = authentice.get();
        if (Objects.isNull(subject)) {
            return null;
        } else {
            return subject;
        }
    }

    public static void setLoginSubject(LoginSubject loginSubject) {
        authentice.set(loginSubject);
    }

    public static void clearLoginId() {
        authentice.remove();
    }
}
