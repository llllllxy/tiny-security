package org.tinycloud.security.util.secure;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 加密工具类 用于前后端密码密文传输
 * RSA非对称加密算法，如果是公钥加密，就得用私钥解密，反过来也一样，私钥加密的就用公钥解密。
 * @author liuxingyu01
 * @version  2022-03-29 10:35
 **/
public class RSAUtil {
    /**
     * 公钥解密
     *
     * @param publicKeyString 公钥
     * @param text            待解密的信息
     * @return 解密后的文本
     */
    public static String decryptByPublicKey(String publicKeyString, String text) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(Base64.getDecoder().decode(text));
        return new String(result);
    }

    /**
     * 私钥加密
     *
     * @param privateKeyString 私钥
     * @param text             待加密的信息
     * @return 加密后的文本
     */
    public static String encryptByPrivateKey(String privateKeyString, String text) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * 私钥解密
     *
     * @param privateKeyString 私钥
     * @param text             待解密的文本
     * @return 解密后的文本
     */
    public static String decryptByPrivateKey(String privateKeyString, String text) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec5 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec5);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(Base64.getDecoder().decode(text));
        return new String(result);
    }

    /**
     * 公钥加密
     *
     * @param publicKeyString 公钥
     * @param text            待加密的文本
     * @return 加密后的文本
     */
    public static String encryptByPublicKey(String publicKeyString, String text) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec2);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * 构建RSA密钥对
     *
     * @return 生成后的公私钥信息
     */
    public static RsaKeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        String publicKeyString = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
        return new RsaKeyPair(publicKeyString, privateKeyString);
    }

    /**
     * RSA密钥对对象
     */
    public static class RsaKeyPair {
        private final String publicKey;
        private final String privateKey;

        public RsaKeyPair(String publicKey, String privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        @Override
        public String toString() {
            return "RsaKeyPair{\n" +
                    "publicKey = " + publicKey  + "\n" +
                    "privateKey = " + privateKey + "\n" +
                    "}";
        }
    }



    /**
     * 测试
     * @param args
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws Exception {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuog+bZpoIjtWR81gR4tnBQrAbn8M6v57hZOOy7uUydGlx7DxTnxeb+IPK9wiC+dBEmkM5PHYLT0pYs7676cMOlK8kzcDC2COq1fPjtLPM2bHeyj6bMlahUoK4df5xb9ojHHuKltyQ+kPrT/4adPvM5+awC2e8n/rpZowGcE05EEgTUZpHDYz3v2AQ2V/7ai5YOtBo9JLTe93Xs+x6A0J4A8GJZN42fcbSUniedDG9xGDzr7ucJvWhF/u5hVwk599kH9+br91Oi2fKHqlM03cmw74mV8qPivaMZeoag6sLDeZHn8AeX4TDsPWXWjZInLrJ/ehbxumNPioCaWxD/ODYQIDAQAB";
        String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6iD5tmmgiO1ZHzWBHi2cFCsBufwzq/nuFk47Lu5TJ0aXHsPFOfF5v4g8r3CIL50ESaQzk8dgtPSlizvrvpww6UryTNwMLYI6rV8+O0s8zZsd7KPpsyVqFSgrh1/nFv2iMce4qW3JD6Q+tP/hp0+8zn5rALZ7yf+ulmjAZwTTkQSBNRmkcNjPe/YBDZX/tqLlg60Gj0ktN73dez7HoDQngDwYlk3jZ9xtJSeJ50Mb3EYPOvu5wm9aEX+7mFXCTn32Qf35uv3U6LZ8oeqUzTdybDviZXyo+K9oxl6hqDqwsN5kefwB5fhMOw9ZdaNkicusn96FvG6Y0+KgJpbEP84NhAgMBAAECggEATwCXWDp2clEpWN3eMk8Tgeos2F/NK9Y+oLN/XkCDYvr9ONdzTGeWY9Kd1Fi2vs3iHJcLlAfuJDLsTWIWm9vnbOhP4BYDnxT1OBLH4NjeUwnr4PjZH6wkP6G9fCvKKPvJnvo+AgibG7IhJqKaZtARVo75rv1jfZe6SXhFeRMAgM9vbFwIgxdzKEGQg32fwU5ZyKsbtHfuZrBfy/Q96wu94+OHVKgtdASfxYmYaNAnRLS6JOt2xQmW0iv43truMd8bqQy4VXaVZtdiDcLNlbV3LSeDw5fAPVuPTaiDu/YvdZd5Dzihj1gvfEuqv7ojsfCX4ib9zb0DRuweLcyjGZsx8QKBgQDdkRGrkWThCzyRg7CFvIceAhXUj3tllUil7cAL9Qvk3YAGryXazHHmzwP5WgC8ayVjM8G+phJCSGLrV/bWO625VKOuSnvQHlrQV+/HfLpEApm/hXHj/Y0y+AmgqSeyah/6AC4KN3BKlNa+Q53iGyrmIJqGpV6lScla2iXwkkEApQKBgQDXhVgQtpSnLFxQGvKjrCxJRJ0ucQFY0T3wqHst36hwd0ecUu8M8BuYc83wjd1EHgEACumZoObly2y9XHvWM7RwRrz32DQpNE/vl2rJH3oygGXw/ZymPkwjmlK5MpyzIZrwvnAXW/abh1W34kNGFh5Jo+e07s6Ln1m3eJLhkkCfDQKBgDiDZApqz1xHTW+gM0opSB1zUrYg0syaQylvduiV3C7IAHuz+OfR9ct1SgIz3rQwcBzZerVyDn4xkGmOyjrihfEbkZRHE0WGOIujolkzix8FusmK8/2/EmDJu0rrWmC7iORvX07jzRR42j01afPeEhcYgdGOJJHsPBucQMkXxNSxAoGBANE8ifUf7U4nyS+UGgFBBHXVgWw3FgGukx3z1DMDMrqNcx6XfbHn4kKuGz/x2uFo57us3IHkLobmahmlkiyxYfqnEorkgi+GtBx9upSsVKx274F6Fv1m+fCOwMVAF9XpSE119ckX5WG1kEjICFwg2SLRWADW3/u5pxZyntcUcFx5AoGBAJMZB+63OoGrj7IYv1pHGCUH746m4+8/+4I83rdvOkPYG76A1bGpVjgl578Koz5wRFIp2Z1vkXzQTA/t35oTwt0YVXcIs7rll6JdD+vz7mSi4VObgxV8DFIMRsWsq1OQb3BOErhefWkOumaSPQmP1fZEAmReQA92Lz/n0fMix5ft";

        // 使用公钥加密
        String encryptedValue = encryptByPublicKey(publicKey, "abcdefg");

        System.out.println(encryptedValue);

        // 使用私钥解密
        String decryptedValue = decryptByPrivateKey(privateKey, encryptedValue);

        System.out.println(decryptedValue);
    }
}
