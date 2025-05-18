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

    public static String getVersion() {
        String appVersion = "";
        Properties properties = new Properties();
        try (InputStream stream = VersionUtil.class.getClassLoader().getResourceAsStream("core.properties")) {
            properties.load(stream);
            if (!properties.isEmpty()) {
                appVersion = properties.getProperty("core.version");
            }
        } catch (IOException e) {
            throw new RuntimeException("getVersion failed: ", e);
        }
        return appVersion;
    }
}
