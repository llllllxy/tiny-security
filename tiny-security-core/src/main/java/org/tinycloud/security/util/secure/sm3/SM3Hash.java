package org.tinycloud.security.util.secure.sm3;

import org.tinycloud.security.util.secure.HexUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SM3Hash {

    /**
     * 原始值
     */
    private String source;

    /**
     * 盐值
     */
    private String salt = "";

    /**
     * 迭代次数（默认1次）
     */
    private int iterations = 1;

    public String getSource() {
        return this.source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSalt() {
        return this.salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public int getIterations() {
        return this.iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public SM3Hash(String source, String salt, int iterations) {
        this.source = source;
        this.salt = salt;
        this.iterations = iterations;
    }

    public SM3Hash(String source, String salt) {
        this.source = source;
        this.salt = salt;
    }

    public SM3Hash(String source) {
        this.source = source;
    }

    public SM3Hash(String source, int iterations) {
        this.source = source;
        this.iterations = iterations;
    }

    /**
     * 返回小写SM3 hash串
     *
     * <p>1.5.0 起 {@code salt} 为 {@code null} 时按空串处理。此前是直接拼 {@code (source + salt)}，
     * {@code null} 会被拼成字面量 {@code "null"}，导致 {@code salt=null} 与 {@code salt="null"}
     * 产生<b>完全相同的哈希</b>（真碰撞）。归一化后 {@code null} 与 {@code ""} 等价，语义与
     * {@code SimpleHash} 的 JDK 分支（{@code salt == null} 视为不加盐）保持一致。
     *
     * <p>此处不再吞异常：原实现在失败时返回预分配的全 0 数组，调用方无法区分"算错了"和"算完了"。
     *
     * @param source 原始值字符串
     * @param salt   盐值，{@code null} 等价于空串
     * @return hash后的字节数组
     */
    private byte[] SM3Encode(String source, String salt) {
        String normalizedSalt = salt == null ? "" : salt;
        byte[] msgBytes = (source + normalizedSalt).getBytes(StandardCharsets.UTF_8);

        byte[] hashedBytes = new byte[32];
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(msgBytes, 0, msgBytes.length);
        sm3Digest.doFinal(hashedBytes, 0);
        return hashedBytes;
    }


    /**
     * 返回小写SM3 hash串
     *
     * <p>此处不再吞异常：原实现在失败时返回预分配的全 0 数组，调用方无法区分"算错了"和"算完了"。
     *
     * @param msgBytes 原始值-字节数组
     * @return hash后的字节数组
     */
    private byte[] SM3Encode(byte[] msgBytes) {
        byte[] hashedBytes = new byte[32];
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(msgBytes, 0, msgBytes.length);
        sm3Digest.doFinal(hashedBytes, 0);
        return hashedBytes;
    }


    /**
     * 返回小写SM3 hash串
     *
     * @param source 原始值字符串
     * @return hash后的字节数组
     */
    private byte[] SM3Encode(String source, String salt, int hashIterations) {
        byte[] hashedBytes;
        // 最少迭代一次
        if (hashIterations < 1) {
            hashIterations = 1;
        }
        hashedBytes = this.SM3Encode(source, salt);
        for (int i = 0; i < hashIterations - 1; i++) {
            hashedBytes = this.SM3Encode(hashedBytes);
        }
        return hashedBytes;
    }


    /**
     * 将将byte[]转为16进制字符串
     *
     * @return 16进制字符串
     */
    public byte[] toBytes() {
        byte[] resultBytes = this.SM3Encode(this.source, this.salt, this.iterations);
        return resultBytes;
    }

    /**
     * 将将byte[]转为16进制字符串
     *
     * @return 16进制字符串
     */
    public String toHex() {
        byte[] resultBytes = this.SM3Encode(this.source, this.salt, this.iterations);
        return HexUtil.bytesToHex(resultBytes);
    }


    /**
     * 将将byte[]转为Base64字符串
     *
     * @return Base64字符串
     */
    public String toBase64() {
        byte[] resultBytes = this.SM3Encode(this.source, this.salt, this.iterations);
        return Base64.getEncoder().encodeToString(resultBytes);
    }


    /**
     * 将将byte[]转为16进制字符串
     *
     * @return 16进制字符串
     */
    @Override
    public String toString() {
        return this.toHex();
    }

}
