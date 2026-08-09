package org.tinycloud.security.util.secure;

import org.tinycloud.security.util.secure.sm3.SM3Hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * SimpleHash 是一个通用的哈希工具类。
 * <p>
 * 支持 JDK 内置算法（MD5、SHA-1、SHA-256 等）以及 SM3 算法（需依赖已封装的 SM3Hash）。
 * 提供盐值支持和多次迭代计算功能，可输出 HEX 或 Base64 字符串。
 * <p>
 * 特性：
 * 1. 盐值仅在第一次迭代中使用，符合 Shiro SimpleHash 行为。
 * 2. 支持自定义迭代次数，保证哈希安全性。
 * 3. 兼容 SM3 与常见 JDK 哈希算法。
 * <p>
 * 示例用法：
 * <pre>
 * String hash = new SimpleHash("SHA-256", "password", "salt", 10).toHex();
 * String sm3Hash = new SimpleHash("SM3", "password", "salt", 3).toBase64();
 * </pre>
 */
public class SimpleHash {

    private final byte[] hashBytes;

    /**
     * 构造方法，创建指定算法、盐值和迭代次数的哈希对象。
     *
     * @param algorithm  算法名称: MD5, SHA-1, SHA-256, SM3
     * @param source     明文字符串
     * @param salt       盐值，null
     * @param iterations 迭代次数，最少1次
     */
    public SimpleHash(String algorithm, String source, String salt, int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be >= 1");
        }
        if ("SM3".equalsIgnoreCase(algorithm)) {
            // 使用现有的 SM3 封装
            SM3Hash sm3 = new SM3Hash(source, salt, iterations);
            this.hashBytes = sm3.toBytes();
        } else {
            this.hashBytes = jdkHash(algorithm, source, salt, iterations);
        }
    }

    /**
     * 构造方法，默认迭代一次。
     *
     * @param algorithm 哈希算法名称
     * @param source    明文字符串
     * @param salt      盐值
     */
    public SimpleHash(String algorithm, String source, String salt) {
        this(algorithm, source, salt, 1);
    }

    /**
     * 构造方法，默认无盐，迭代一次。
     *
     * @param algorithm 哈希算法名称
     * @param source    明文字符串
     */
    public SimpleHash(String algorithm, String source) {
        this(algorithm, source, null, 1);
    }

    /**
     * 将哈希结果转为十六进制字符串表示。
     *
     * @return 哈希结果的 HEX 字符串
     */
    public String toHex() {
        return HexUtil.bytesToHex(hashBytes);
    }

    /**
     * 将哈希结果转为 Base64 字符串表示。
     *
     * @return 哈希结果的 Base64 字符串
     */
    public String toBase64() {
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * 使用 JDK 内置算法进行哈希计算。
     * <p>
     * 盐值仅在第一次迭代中加到消息摘要中，每次迭代都使用上一次哈希结果。
     *
     * @param algorithm  算法名称
     * @param source     明文字符串
     * @param salt       盐值，可为 null
     * @param iterations 迭代次数，至少 1
     * @return 哈希结果字节数组
     */
    private byte[] jdkHash(String algorithm, String source, String salt, int iterations) {
        try {
            byte[] data = source.getBytes(StandardCharsets.UTF_8);
            byte[] saltBytes = salt != null ? salt.getBytes(StandardCharsets.UTF_8) : null;

            MessageDigest digest = MessageDigest.getInstance(algorithm);
            for (int i = 0; i < iterations; i++) {
                digest.reset();

                // 仅第一次迭代加盐
                if (i == 0 && saltBytes != null) {
                    digest.update(saltBytes);
                }

                data = digest.digest(data);
            }
            return data;
        } catch (Exception e) {
            throw new RuntimeException("Hash failed", e);
        }
    }


    /**
     * 简单测试示例
     */
    public static void main(String[] args) {
        String password = "123456";
        String salt = "323@#@$1234da";

        System.out.println("MD5 HEX: " + new SimpleHash("MD5", password, salt, 2).toHex());
        System.out.println("SHA-256 BASE64: " + new SimpleHash("SHA-256", password, salt, 10).toBase64());
        System.out.println("SHA-256 HEX (no salt): " + new SimpleHash("SHA-256", password).toHex());
        System.out.println("SM3 HEX: " + new SimpleHash("SM3", password, salt, 3).toHex());
    }
}