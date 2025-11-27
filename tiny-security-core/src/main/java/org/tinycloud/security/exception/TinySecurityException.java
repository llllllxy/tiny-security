package org.tinycloud.security.exception;


import org.tinycloud.security.consts.AuthConsts;

public class TinySecurityException extends RuntimeException {
    private static final long serialVersionUID = 2413958299445359500L;

    private int code;

    public void setCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public TinySecurityException(int code, String message) {
        super(message);
        this.code = code;
    }

    public TinySecurityException(String message) {
        super(message);
        this.code = AuthConsts.CODE_OTHER_ERROR;
    }

    public TinySecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
