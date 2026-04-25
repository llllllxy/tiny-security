package org.tinycloud.security.util;

import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;


/**
 * 一些公共的，不好分类的工具方法放在这里
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class CommonUtil {
    private final static String TIME_FORMAT = "yyyyMMddHHmmss";

    /**
     * AntPathMatcher 中的方法是线程安全的，通常建议在应用中共享同一个实例以减少开销：
     */
    private static final PathMatcher MATCHER = new AntPathMatcher();

    /**
     * 获取当前时间 比如 DateTool.getCurrentTime(); 返回值为 20120515234420
     *
     * @return dateTimeStr yyyyMMddHHmmss
     */
    public static String getCurrentTime() {
        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT);
        return dateTimeFormatter.format(dateTime);
    }

    /**
     * 在当前时间上减少 若干秒
     *
     * @param secondsCount 要减少的秒数
     * @return 固定格式 yyyyMMddHHmmss
     */
    public static String currentTimeMinusSeconds(int secondsCount) {
        LocalDateTime time = LocalDateTime.now();
        LocalDateTime newTime = time.minusSeconds(secondsCount); // 减少几秒
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT);
        return dateTimeFormatter.format(newTime);
    }

    /**
     * 生成指定长度的随机字符串（包括大小写字母，数字和下划线）
     *
     * @param length 字符串的长度
     * @return 一个随机字符串
     */
    public static String getRandomString(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = ThreadLocalRandom.current().nextInt(63);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    /**
     * 字符串模糊匹配
     * <p> example:
     * <p> user* user-add   --  true
     * <p> user* art-add    --  false
     * <p> art.* art.add    --  true
     * <p> art.* art-add    --  false
     *
     * @param pattern 表达式
     * @param str     待匹配的字符串
     * @return 是否可以匹配
     */
    public static boolean vagueMatch(String pattern, String str) {
        // 两者均为 null 时，直接返回 true
        if (pattern == null && str == null) {
            return true;
        }
        // 两者其一为 null 时，直接返回 false
        if (pattern == null || str == null) {
            return false;
        }
        // 如果表达式不带有*号，则只需简单equals即可 (这样可以使速度提升200倍左右)
        if (!pattern.contains("*")) {
            return pattern.equals(str);
        }
        // 深入匹配
        return vagueMatchMethod(pattern, str);
    }

    /**
     * 字符串模糊匹配
     *
     * @param pattern 表达式
     * @param str     待匹配的字符串
     * @return 是否可以匹配
     */
    private static boolean vagueMatchMethod(String pattern, String str) {
        int m = str.length();
        int n = pattern.length();
        boolean[][] dp = new boolean[m + 1][n + 1];
        dp[0][0] = true;
        for (int i = 1; i <= n; ++i) {
            if (pattern.charAt(i - 1) == '*') {
                dp[0][i] = true;
            } else {
                break;
            }
        }
        for (int i = 1; i <= m; ++i) {
            for (int j = 1; j <= n; ++j) {
                if (pattern.charAt(j - 1) == '*') {
                    dp[i][j] = dp[i][j - 1] || dp[i - 1][j];
                } else if (str.charAt(i - 1) == pattern.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                }
            }
        }
        return dp[m][n];
    }


    /**
     * 匹配配置路径集合和当前请求路径(基于spring自带的AntPathMatcher，支持spring通配符'{}','*','**','?')
     *
     * @param configPaths 配置路径
     * @param requestPath 请求路径
     * @return false未匹配成功 true匹配成功
     */
    public static boolean matchPaths(Collection<String> configPaths, String requestPath) {
        if (CollectionUtils.isEmpty(configPaths) || !StringUtils.hasLength(requestPath)) {
            return false;
        }
        for (String configPath : configPaths) {
            if (StringUtils.hasLength(configPath) && MATCHER.match(configPath, requestPath)) {
                return true;
            }
        }
        return false;
    }


    /**
     * 合并两个字符串数组并去除重复元素
     *
     * @param arr1 第一个字符串数组
     * @param arr2 第二个字符串数组
     * @return 合并后去重的字符串数组，如果两个数组都为null则返回空数组
     */
    public static String[] mergeAndDeduplicate(String[] arr1, String[] arr2) {
        Set<String> set = new LinkedHashSet<>();
        if (arr1 != null && arr1.length > 0) {
            Collections.addAll(set, arr1);
        }
        if (arr2 != null && arr2.length > 0) {
            Collections.addAll(set, arr2);
        }
        return set.toArray(new String[0]);
    }
}
