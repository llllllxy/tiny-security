package org.tinycloud.security.util;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilTest {

    private Map<String, String> payload() {
        Map<String, String> payload = new HashMap<>();
        payload.put("credentials", "cred-abc-123");
        return payload;
    }

    @Test
    void shouldSignAndVerifyClaims() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        Map<String, String> claims = JwtUtil.getClaims("secret-1", token);

        assertNotNull(claims);
        assertEquals("cred-abc-123", claims.get("credentials"));
        assertEquals("subject-1", JwtUtil.getSubject(token));
    }

    @Test
    void shouldRejectWrongSecret() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        assertNull(JwtUtil.getClaims("secret-2", token));
    }

    @Test
    void shouldRejectTamperedToken() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        assertNull(JwtUtil.getClaims("secret-1", token + "x"));
        assertNull(JwtUtil.getClaims("secret-1", "not-a-jwt"));
    }

    @Test
    void shouldRejectExpiredToken() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), -10);

        assertNull(JwtUtil.getClaims("secret-1", token));
    }

    @Test
    void shouldApplyCustomExpiry() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 3600);
        Map<String, String> claims = JwtUtil.getClaims("secret-1", token);
        assertNotNull(claims);

        long exp = Long.parseLong(claims.get("exp"));
        long iat = Long.parseLong(claims.get("iat"));

        assertEquals(3600_000L, exp - iat, 1_000L);
    }

    @Test
    void shouldThrowWhenSecretMissingOnSign() {
        Map<String, String> payload = payload();

        assertThrows(IllegalArgumentException.class, () -> JwtUtil.sign(null, "subject-1", payload));
        assertThrows(IllegalArgumentException.class, () -> JwtUtil.sign("", "subject-1", payload));
    }

    @Test
    void shouldThrowWhenSecretMissingOnGetClaims() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        assertThrows(IllegalArgumentException.class, () -> JwtUtil.getClaims(null, token));
        assertThrows(IllegalArgumentException.class, () -> JwtUtil.getClaims("", token));
    }

    @Test
    void shouldVerifySubjectWithValidSecret() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        assertEquals("subject-1", JwtUtil.getVerifiedSubject("secret-1", token));
    }

    @Test
    void shouldRejectSubjectWithWrongSecretOrTamperedToken() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), 60);

        assertNull(JwtUtil.getVerifiedSubject("secret-2", token));
        assertNull(JwtUtil.getVerifiedSubject("secret-1", token + "x"));
        assertNull(JwtUtil.getVerifiedSubject("secret-1", "not-a-jwt"));
    }

    @Test
    void shouldRejectSubjectWhenExpired() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload(), -10);

        assertNull(JwtUtil.getVerifiedSubject("secret-1", token));
    }

    @Test
    void shouldThrowWhenPayloadNullOnSign() {
        assertThrows(IllegalArgumentException.class, () -> JwtUtil.sign("secret-1", "subject-1", null, 60));
        assertThrows(IllegalArgumentException.class, () -> JwtUtil.sign("secret-1", "subject-1", null));
    }

    @Test
    void shouldUseDefaultSubjectWhenEmpty() {
        String token = JwtUtil.sign("secret-1", null, payload(), 60);

        assertEquals("tiny-security", JwtUtil.getSubject(token));
    }

    @Test
    void shouldUseDefaultExpiryWhenNotSpecified() {
        String token = JwtUtil.sign("secret-1", "subject-1", payload());
        Map<String, String> claims = JwtUtil.getClaims("secret-1", token);
        assertNotNull(claims);

        long exp = Long.parseLong(claims.get("exp"));
        long iat = Long.parseLong(claims.get("iat"));

        // 默认有效期30天
        assertTrue(exp - iat >= 30L * 24 * 60 * 60 * 1000 - 1_000L);
    }
}
