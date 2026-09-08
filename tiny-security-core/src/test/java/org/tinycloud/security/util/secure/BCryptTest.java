package org.tinycloud.security.util.secure;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BCrypt 密码哈希测试：验证 hashpw/checkpw 往返正确性与随机盐特性。
 */
class BCryptTest {

    @Test
    void shouldMatchPasswordAfterHashAndCheck() {
        String password = "P@ssw0rd-2026";
        String hashed = BCrypt.hashpw(password, BCrypt.gensalt());

        assertTrue(BCrypt.checkpw(password, hashed));
    }

    @Test
    void shouldRejectWrongPassword() {
        String hashed = BCrypt.hashpw("correct-password", BCrypt.gensalt());

        assertFalse(BCrypt.checkpw("wrong-password", hashed));
    }

    @Test
    void shouldGenerateDifferentHashesWithRandomSalt() {
        String password = "same-password";
        String hash1 = BCrypt.hashpw(password, BCrypt.gensalt());
        String hash2 = BCrypt.hashpw(password, BCrypt.gensalt());

        assertNotEquals(hash1, hash2);
        assertTrue(BCrypt.checkpw(password, hash1));
        assertTrue(BCrypt.checkpw(password, hash2));
    }

    @Test
    void shouldRejectEmptyPassword() {
        String hashed = BCrypt.hashpw("real-password", BCrypt.gensalt());

        assertFalse(BCrypt.checkpw("", hashed));
    }
}
