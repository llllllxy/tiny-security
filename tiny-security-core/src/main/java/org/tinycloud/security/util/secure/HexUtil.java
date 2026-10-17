package org.tinycloud.security.util.secure;

/**
 * 十六进制工具类。
 *
 * <p>原先还带有 {@code hexToBytes(String)} / {@code hexToByte(String)} 两个方法，
 * 但全项目无人调用（框架内没有「十六进制字符串 → 字节」的需求），已一并删除 ——
 * 保留无调用方的公开方法等于长期维护一份无人验证的代码。
 */
public class HexUtil {

    private HexUtil() {
    }

    /**
     * 字节数组转16进制
     *
     * @param bytes 需要转换的byte数组
     * @return 转换后的Hex字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

}
