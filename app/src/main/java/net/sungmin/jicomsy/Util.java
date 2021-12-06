package net.sungmin.jicomsy;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Util {

    static final String TIME_STAMP_FORMAT = "yy.MM.dd HH:mm:ss";

    static String getTimeStamp() {
        SimpleDateFormat format = new SimpleDateFormat(TIME_STAMP_FORMAT);
        return format.format(new Date());
    }
}
