package org.tinycloud.security.util;

import org.tinycloud.security.util.idgen.NanoId;

import java.util.UUID;

/**
 * token字符串生成工具类
 *
 * @author liuxingyu01
 * @version 2022-05-21 9:53
 **/
public class CredentialsGenUtil {

    final static String TOKEN_STYLE_UUID = "uuid";

    final static String TOKEN_STYLE_RANDOM128 = "random128";

    final static String TOKEN_STYLE_NANOID = "nanoid";

    /**
     * 根据参数生存不同风格的token字符串
     * <p>
     * 注意：凭证是会话的唯一钥匙，必须不可预测。仅 {@code uuid} / {@code random128} / {@code nanoid}
     * 三类具备密码学随机性，可用于生产；其余取值或非法取值一律回退为 uuid。
     *
     * @param tokenStyle token风格
     * @return token字符串
     */
    public static String generate(String tokenStyle) {
        if (tokenStyle == null || tokenStyle.isEmpty()) {
            tokenStyle = TOKEN_STYLE_UUID;
        }
        String token;
        switch (tokenStyle) {
            case TOKEN_STYLE_UUID:
                token = UUID.randomUUID().toString().replace("-", "");
                break;
            case TOKEN_STYLE_RANDOM128:
                token = CommonUtil.getRandomString(128);
                break;
            case TOKEN_STYLE_NANOID:
                token = NanoId.INSTANCE.randomNanoId();
                break;
            default:
                // 其余风格（含已移除的 snowflake/objectid/ulid）一律回退为 uuid，保证凭证不可预测
                token = UUID.randomUUID().toString().replace("-", "");
                break;
        }
        return token;
    }

}
