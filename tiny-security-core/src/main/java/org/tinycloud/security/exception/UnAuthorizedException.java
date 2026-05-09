package org.tinycloud.security.exception;

import org.tinycloud.security.consts.AuthConsts;

import java.io.Serial;

/**
 * 未登录或会话已失效-异常
 */
public class UnAuthorizedException extends TinySecurityException {
    @Serial
    private static final long serialVersionUID = 8109117719383003891L;

    public UnAuthorizedException() {
        super(AuthConsts.CODE_UNAUTHORIZED, "未登录或会话已失效！");
    }

    public UnAuthorizedException(String message) {
        super(AuthConsts.CODE_UNAUTHORIZED, message);
    }
}
