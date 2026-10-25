package org.tinycloud.security.util;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link VersionUtil} 的回归测试。
 *
 * <p><b>核心回归点</b>：{@code core.properties} 缺失时不得抛 NPE。
 *
 * <p>原实现直接 {@code properties.load(getResourceAsStream(...))}：资源不存在时
 * {@code getResourceAsStream} 返回 {@code null}，而 {@code Properties.load(null)} 抛的是
 * {@link NullPointerException} —— **不是** {@code IOException}，因此不会被原有的
 * {@code catch (IOException)} 接住，会一路冒到调用方。而调用方是启动流程
 * （打印 banner 与 "started successfully"），等于一个仅用于展示的资源缺失
 * 就能让框架起不来。
 *
 * <p>验证方式：用屏蔽了 {@code core.properties} 的类加载器重新加载 {@code VersionUtil}，
 * 使其内部 {@code getClassLoader().getResourceAsStream(...)} 真的返回 null，
 * 再从外部观察它的行为。
 *
 * @author liuxingyu01
 */
class VersionUtilTest {

    /**
     * 资源存在时能读出真实版本号（构建期由 maven-resources-plugin 过滤替换）。
     */
    @Test
    void shouldReadVersionWhenResourceExists() {
        String version = VersionUtil.getVersion();

        assertNotNull(version, "不应返回 null");
        assertFalse(version.isEmpty(), "测试类路径下 core.properties 应存在且包含 core.version");
    }

    /**
     * 资源缺失时必须返回空串，而不是抛 NPE。
     */
    @Test
    void shouldReturnEmptyStringWhenResourceMissing() throws Exception {
        ClassLoader isolated = new BlockingClassLoader(currentClasspathUrls(), "core.properties");
        try {
            Class<?> utilClass = Class.forName("org.tinycloud.security.util.VersionUtil", true, isolated);

            // 先确认隔离生效：该加载器确实看不到 core.properties
            assertNull(isolated.getResourceAsStream("core.properties"),
                    "前置条件：隔离加载器不应能找到 core.properties");

            Object result = assertDoesNotThrow(
                    () -> utilClass.getMethod("getVersion").invoke(null),
                    "资源缺失时 getVersion 不应抛异常（原实现会抛 NPE）");
            assertEquals("", result, "资源缺失时应降级为空串");
        } finally {
            ((URLClassLoader) isolated).close();
        }
    }

    /**
     * 当前测试运行时的类路径，转成 URL 供隔离加载器使用。
     */
    private static URL[] currentClasspathUrls() {
        String classpath = System.getProperty("java.class.path", "");
        List<URL> urls = new ArrayList<>();
        for (String entry : classpath.split(File.pathSeparator)) {
            if (entry.isEmpty()) {
                continue;
            }
            try {
                urls.add(new File(entry).toURI().toURL());
            } catch (Exception e) {
                // 忽略无法转换的条目，不影响本测试目的
            }
        }
        return urls.toArray(new URL[0]);
    }

    /**
     * 能加载类与其它资源、但刻意"看不见"指定资源名的类加载器。
     *
     * <p>父加载器取 platform classloader：它包含 JDK 类，但不含测试类路径，
     * 因此 {@code core.properties} 只能从本加载器自身的 URL 里找，从而可以被精确屏蔽。
     */
    private static class BlockingClassLoader extends URLClassLoader {
        private final String blocked;

        BlockingClassLoader(URL[] urls, String blocked) {
            super(urls, ClassLoader.getPlatformClassLoader());
            this.blocked = blocked;
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            return this.blocked.equals(name) ? null : super.getResourceAsStream(name);
        }

        @Override
        public URL getResource(String name) {
            return this.blocked.equals(name) ? null : super.getResource(name);
        }
    }
}
