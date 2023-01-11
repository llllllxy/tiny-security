package org.bluewind.authclient.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;


/**
 * 一些公共的，不好分类的工具方法放在这里
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
     * 在当前时间上增加 若干秒
     *
     * @param secondsCount 要增加的秒数
     * @return 固定格式 yyyyMMddHHmmss
     */
    public static String currentTimePlusSeconds(int secondsCount) {
        LocalDateTime time = LocalDateTime.now();
        LocalDateTime newTime = time.plusSeconds(secondsCount); // 增加几秒
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT);
        return dateTimeFormatter.format(newTime);
    }


    /**
     *
     * 字符串转时间 然后比较大小
     *
     * @param tempTime 要比较的时间字符串，格式为yyyyMMddHHmmss，
     * @return true：输入时间大于当前时间 ，false：输入时间小于当前时间
     */
    public static boolean timeCompare (String tempTime) {
        DateTimeFormatter dtf2 = DateTimeFormatter.ofPattern(TIME_FORMAT);
        LocalDateTime localDateTime = LocalDateTime.parse(tempTime, dtf2);
        return localDateTime.isAfter(LocalDateTime.now());
    }


    public static void main(String[] args) {

        System.out.println(getCurrentTime());

        System.out.println(currentTimePlusSeconds(30));

        System.out.println(timeCompare("20230110160622"));
    }


}
