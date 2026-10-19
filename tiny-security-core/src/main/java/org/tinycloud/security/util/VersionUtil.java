package org.tinycloud.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * <p>
 * 获取pom当前版本号
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-04-16 11:11
 */
public class VersionUtil {
    private VersionUtil() {
    }

    /**
     * 读取 {@code core.properties} 中的版本号。
     *
     * <p>资源缺失时返回空串而不是抛异常：版本号只用于启动日志与 banner 展示，
     * 不应因为一个资源文件没打进包就让框架启动失败。
     *
     * @return 版本号；资源缺失或属性不存在时返回空串
     */
    public static String getVersion() {
        String appVersion = "";
        Properties properties = new Properties();
        try (InputStream stream = VersionUtil.class.getClassLoader().getResourceAsStream("core.properties")) {
            // 资源不存在时 getResourceAsStream 返回 null，而 Properties.load(null) 会抛 NPE；
            // NPE 不是 IOException，不会被下面的 catch 接住，会直接冒到调用方（启动流程）
            if (stream == null) {
                return appVersion;
            }
            properties.load(stream);
            if (!properties.isEmpty()) {
                String version = properties.getProperty("core.version");
                if (version != null) {
                    appVersion = version;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("getVersion failed: ", e);
        }
        return appVersion;
    }
}
