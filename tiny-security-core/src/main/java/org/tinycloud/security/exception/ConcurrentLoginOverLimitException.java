package org.tinycloud.security.exception;

import org.tinycloud.security.consts.AuthConsts;

/**
 * <p>
 * 并发登录超过最大限制异常
 * </p>
 *
 * @author liuxingyu01
 * @since 2025/11/27 21:58
 */
public class ConcurrentLoginOverLimitException extends TinySecurityException {

    public ConcurrentLoginOverLimitException() {
        super(AuthConsts.CODE_CONCURRENT_LOGIN_OVER_LIMIT, "并发登录超过最大限制!");
    }

    public ConcurrentLoginOverLimitException(String message) {
        super(AuthConsts.CODE_CONCURRENT_LOGIN_OVER_LIMIT, message);
    }
}
