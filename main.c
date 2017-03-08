#include <stdio.h>
#include "ilog.h"
#include <vld.h>

int main(void)
{
    //char buf[31] = "\r\n中文字符串测试😂...";
	char buf[31] = "\r\n中文字符串测试...";
 
    printf("testcase for log...\n");
    logDebug("this is a %s message", ilogLevelToString((LogLevel)1));
    logInfo("this is a %s message", ilogLevelToString((LogLevel)2));
    logNotice("this is a %s message", ilogLevelToString((LogLevel)3));
    logWarn("this is a %s message", ilogLevelToString((LogLevel)4));
    logError("this is a %s message", ilogLevelToString((LogLevel)5));
    logFatal("this is a %s message", ilogLevelToString((LogLevel)6));

    printf("\ntestcase for hexlog...\n");
    hexLogDebug(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)1));
    hexLogInfo(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)2));
    hexLogNotice(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)3));
    hexLogWarn(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)4));
    hexLogError(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)5));
    hexLogFatal(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)6));

    printf("\ntestcase for logIf...\n");
    logIf(1, 1, "this is a %s message for logIf", ilogLevelToString((LogLevel)1));
    logIf(1, 2, "this is a %s message for logIf", ilogLevelToString((LogLevel)2));
    logIf(1, 3, "this is a %s message for logIf", ilogLevelToString((LogLevel)3));
    logIf(1, 4, "this is a %s message for logIf", ilogLevelToString((LogLevel)4));
    logIf(1, 5, "this is a %s message for logIf", ilogLevelToString((LogLevel)5));
    logIf(1, 6, "this is a %s message for logIf", ilogLevelToString((LogLevel)6));

    printf("\ntestcase for logIf...\n");
    hexLogIf(1, 1, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)1));
    hexLogIf(1, 2, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)2));
    hexLogIf(1, 3, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)3));
    hexLogIf(1, 4, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)4));
    hexLogIf(1, 5, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)5));
    hexLogIf(1, 6, buf, sizeof(buf), "this is a %s message for logIf", ilogLevelToString((LogLevel)6));

	ilogCleanup();	
    return 0;
}
