package org.tinycloud.security.exception;


import org.tinycloud.security.consts.AuthConsts;

public class AuthException extends RuntimeException {
    private static final long serialVersionUID = 2413958299445359500L;

    private int code;

    public void setCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public AuthException(int code, String message) {
        super(message);
        this.code = code;
    }

    public AuthException(String message) {
        super(message);
        this.code = AuthConsts.CODE_OTHER_ERROR;
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
