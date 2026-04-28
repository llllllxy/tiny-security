package org.tinycloud.security.authorization;

/**
 * 授权决策结果
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class AuthorizationDecision {
    private final boolean granted;

    private AuthorizationDecision(boolean granted) {
        this.granted = granted;
    }

    /**
     * 创建授权通过决策。
     *
     * @return 授权通过
     */
    public static AuthorizationDecision grant() {
        return new AuthorizationDecision(true);
    }

    /**
     * 创建授权拒绝决策。
     *
     * @return 授权拒绝
     */
    public static AuthorizationDecision deny() {
        return new AuthorizationDecision(false);
    }

    /**
     * 判断是否授权通过。
     *
     * @return true-通过，false-拒绝
     */
    public boolean isGranted() {
        return granted;
    }
}
