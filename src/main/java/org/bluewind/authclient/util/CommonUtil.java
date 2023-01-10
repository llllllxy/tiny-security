package org.bluewind.authclient.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CommonUtil {

    /**
     * 求两个时间字符串的差（格式必须为yyyyMMddHHmmss）
     *
     * @param start 开始时间
     * @param end 结束时间
     * @return 秒数
     */
    public static int getBetweenSecond(String start, String end) {
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
        Date startDate;
        Date endDate;
        try {
            startDate = format.parse(start);
            endDate = format.parse(end);
            try {
                long ss = 0;
                if (startDate.before(endDate)) {
                    ss = endDate.getTime() - startDate.getTime();
                } else {
                    ss = startDate.getTime() - endDate.getTime();
                }
                return (int) (ss / (1000));
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            }
        } catch (ParseException e1) {
            e1.printStackTrace();
            return -1;
        }
    }
}
