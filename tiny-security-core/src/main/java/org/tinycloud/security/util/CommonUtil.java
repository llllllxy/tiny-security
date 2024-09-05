package org.tinycloud.security.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
}
