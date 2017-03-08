## ilog
自用输出日志的库，使用C语言编写
跨平台，支持Windows,Linux,Mac

### 简单用法
* 直接使用相关宏就可以输入日志到stdout
* 也可以使用**ilogSetStyle**函数自定义输出格式
* 自定义输出介质(stdout,文件，syslog,或者写个回调函数输出到自定义位置
* 支持同时输出到多个位置，只需要使用**ilogCreate**函数创建个对象然后调用**ilogAddLog**添加这个对象，就能同时输出到多个位置
* 详细的说明都在*ilog.h*中
* TODO: 日志按大小或者时间备份

### 例子
```c
#include <stdio.h>
#include "ilog.h"

static void ilog_init()
{
    ilogInit();
    // 依次输出文件名，所在行数，所在函数的名字，日志内容
    // 格式化字符串类似于printf，在后面会有详细的说明
    ilogSetStyleFormat(NULL, "%S:%L:%F\n%f");
}

int main()
{
    char buf[31] = "\r\n中文字符串测试...";
    ilog_init();	// 甚至可以不用调用,默认会输出到stdout
    logDebug("this is a %s message", ilogLevelToString((LogLevel)1));
    hexLogInfo(buf, sizeof(buf), "this is a %s message for hexlog", ilogLevelToString((LogLevel)2));
    ilogCleanup();
    return 0;
}
```

### ilog输出流程  
日志句柄集合->日志句柄->输出。

### ilog结构  
* 日志等级	ilog_setloglevel
	* null		(不输出日志)
	* debug		(最详细的输出，debug时使用)
	* info		(普通信息等级)
	* notice 	(重要的信息)
	* warning	(警告信息)
	* error		(错误信息)
    * fatal		(致命错误)
* 输出介质	ilog_setoutput
	* 文件
	* stdout
	* stderr
	* syslog
	* callback	(用户自定义输出方式)
	* null		(不在创建对象时立即指定，输出时如果依然为空，则不输出)
* 输出风格	ilogSetStyle && ilogSetStyleCallback
	* setstyle
		* date			%d	(YYYY-MM-DD)
		* datetime		%D	(YYYY-MM-dd HH:mm:ss)
		* datetimems 	%M	(YYYY-MM-dd HH:mm:ss.ms)	支持设置宽度，表示毫秒的显示的位数，范围：1-6
		* loglevel		%l								支持宽度控制，默认右对齐，使用'-'号左对齐
		* source		%S	\_\_FILE\_\_				支持宽度控制，默认右对齐，使用'-'号左对齐
		* line			%L	\_\_LINE\_\_				支持宽度控制，默认右对齐，使用'-'号左对齐，中间数字以0开始，则用0填充
		* function		%F	\_\_func\_\_				支持宽度控制，默认右对齐，使用'-'号左对齐
		* pid			%p								支持宽度控制，默认右对齐，使用'-'号左对齐，中间数字以0开始，则用0填充
		* tid			%t								支持宽度控制，默认右对齐，使用'-'号左对齐，中间数字以0开始，则用0填充
		* usertag		%u								支持宽度控制，默认右对齐，使用'-'号左对齐，中间数字以0开始，则用0填充
		* text			%f								不支持宽度控制。
	* callback
* 日志选项	ilogSetOpt(log, opt, ...)
	* overwrite?		(默认是追加，除非用户)
	* rotatemode		(按大小或者时间转档，可以同时使用)
		* size			(文件名：原文件名[.时间].序号)
		* day			(文件名：原文件名.时间[.序号])
		* hour

### 日志集相关函数
```
ilogCreate(loglevel, type, ...)
ilogDestroy(ilog) *同时从日志句柄集中删除此句柄*  
ilogSetLevel(loglevel)  
ilogSetOutput(logtype, ...)  
ilogSetTag(tag)  
ilogSetOpt(ilog, opt, ...)  
ilogSetStyle(styleType, ...)  
ilogSetStyleFormat(format)  
ilogSetStyleCallback(callback)


ilogInit()  
ilogCleanup() *已添加log不需要手动调用ilogDestroy()*  
ilogAddLog(ilog)  
```
*** 不提供removeLog函数，使用ilogDestroy代替 ***  
*** 全局只存在一个日志句柄集对象，用来管理所有的日志句柄，不再提供其它函数（比如获取已有的句柄）,以强制用户在一段函数里完成日志设置的相关工作 ***
  
### 普通函数
ilogWrite(loglevel, source, line, func, format, ...)
ilogWriteHex(loglevel, source, line, func, buf, len, format, ...)
ilogLevelToString(loglevel)

### 相关宏
```
logDebug(fmt, args...)
logInfo(fmt, args...)
logNotice(fmt, args...)
logWarn(fmt, args...)
logError(fmt, args...)
logFatal(fmt, args...)

hexLogDebug(buf, len, fmt, args...)
hexLogInfo(buf, len, fmt, args...)
hexLogNotice(buf, len, fmt, args...)
hexLogWarn(buf, len, fmt, args...)
hexLogError(buf, len, fmt, args...)
hexLogFatal(buf, len, fmt, args...)

logIf(expr, level, format, args...)
hexLogIf(expr, level, buf, len, fmt, args...)
``` 
