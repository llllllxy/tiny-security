package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.session.SingleSessionRepository;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@code AuthProvider#deleteByToken} 与 {@code getToken} 系列的回归。
 *
 * <p>这两个方法是公开 API，但此前没有任何用例覆盖：{@code deleteByToken} 一次都没被调用过，
 * {@code getToken} 只有间接用例。{@code deleteByToken} 的容错分支尤其值得锁定 ——
 * 它内部会先验签再删除，任何异常都被吞成 {@code false}，若吞错了地方会把「删失败」
 * 静默成「删成功」。
 *
 * @author liuxingyu01
 */
class AuthProviderDeleteByTokenTest {

    private SingleSessionRepository repository;
    private AuthProvider authProvider;

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, new MockHttpServletResponse()));
        repository = new SingleSessionRepository();
        authProvider = new AuthProvider(repository, properties(), null);
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * 正常路径：用 token 删除会话后，凭证应当真的失效。
     */
    @Test
    void shouldDeleteSessionByToken() {
        String token = authProvider.login(10001L, null);
        String credentials = credentialsOf(token);
        assertTrue(repository.checkByCredentials(credentials), "登录后凭证应有效");

        assertTrue(authProvider.deleteByToken(token), "删除应返回 true");

        assertFalse(repository.checkByCredentials(credentials), "删除后凭证必须失效");
        assertNull(repository.getSubject(credentials), "删除后不应再读到会话");
    }

    /**
     * 删除只影响目标会话：同一账号的其它会话必须保留（这是「定向下线」的语义）。
     */
    @Test
    void shouldOnlyDeleteTargetSession() {
        String tokenA = authProvider.login(10001L, null);
        String tokenB = authProvider.login(10001L, null);
        String credentialsA = credentialsOf(tokenA);
        String credentialsB = credentialsOf(tokenB);

        assertTrue(authProvider.deleteByToken(tokenA));

        assertFalse(repository.checkByCredentials(credentialsA), "A 应被删除");
        assertTrue(repository.checkByCredentials(credentialsB), "B 不应受影响");
    }

    /**
     * 伪造 token（签名不匹配）不得删除任何会话 —— 否则等于任何人拿到别人的凭证串
     * 就能踢下线，且验签这一层形同虚设。
     */
    @Test
    void shouldNotDeleteWhenTokenSignatureInvalid() {
        String token = authProvider.login(10001L, null);
        String credentials = credentialsOf(token);
        // 保留正确的 credentials，但把签名改坏
        String tampered = credentials + "." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        assertFalse(authProvider.deleteByToken(tampered), "验签失败应返回 false");
        assertTrue(repository.checkByCredentials(credentials), "原始会话不应被删除");
    }

    /**
     * 与签名不匹配的 credentials（即用别人的凭证串 + 自己算的签名）同样不得删除，
     * 因为签名覆盖了 credentials 本体。
     */
    @Test
    void shouldNotDeleteWhenCredentialsTampered() {
        String tokenA = authProvider.login(10001L, null);
        String credentialsA = credentialsOf(tokenA);
        String signatureA = signatureOf(tokenA);
        // 把 A 的凭证串换成「另一个凭证 + A 的签名」：签名与凭证不再匹配
        String forged = "00000000000000000000000000000000." + signatureA;

        assertFalse(authProvider.deleteByToken(forged), "credentials 被替换后签名不匹配，应拒绝");
        assertTrue(repository.checkByCredentials(credentialsA), "A 的会话不应被删除");
    }

    /**
     * 空 token 是调用方的参数错误，必须抛出明确的断言异常，而不是静默返回 false
     * （否则调用方无法区分「参数写错」与「会话本来就不存在」）。
     */
    @Test
    void shouldRejectBlankToken() {
        assertThrows(IllegalArgumentException.class, () -> authProvider.deleteByToken(null));
        assertThrows(IllegalArgumentException.class, () -> authProvider.deleteByToken(""));
        assertThrows(IllegalArgumentException.class, () -> authProvider.deleteByToken("   "));
    }

    /**
     * 格式非法的 token（不含分隔符）应返回 false 而不是抛异常 —— 调用方通常拿它当
     * 「是否删除成功」用，不应被异常打断。
     */
    @Test
    void shouldReturnFalseOnMalformedTokenInsteadOfThrowing() {
        assertFalse(authProvider.deleteByToken("no-separator-here"));
        assertFalse(authProvider.deleteByToken("a.b.c"));
    }

    /**
     * 已登录态下 getToken() 与 login() 返回值一致；未登录时抛 401。
     */
    @Test
    void getTokenShouldThrowWhenNotLoggedIn() {
        assertThrows(UnAuthorizedException.class, authProvider::getToken);
        assertThrows(UnAuthorizedException.class, authProvider::getRawToken);
    }

    private static String credentialsOf(String token) {
        String signed = token.substring("Bearer ".length());
        return signed.substring(0, signed.lastIndexOf('.'));
    }

    private static String signatureOf(String token) {
        String signed = token.substring("Bearer ".length());
        return signed.substring(signed.lastIndexOf('.') + 1);
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setTokenSecret("test-token-secret-for-delete-by-token!!");
        return properties;
    }
}
