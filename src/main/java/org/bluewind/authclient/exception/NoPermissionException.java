package org.bluewind.authclient.exception;


import org.bluewind.authclient.consts.AuthConsts;

/**
 * 无权限访问-异常
 */
public class NoPermissionException extends AuthException {
    private static final long serialVersionUID = 8109117719383003895L;

    public NoPermissionException() {
        super(AuthConsts.CODE_NO_PERMISSION, "无权限访问！");
    }
}
