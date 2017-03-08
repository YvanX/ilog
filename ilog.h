/*
 * ilog - log function libary in c
 * auther : YvanX
 */

#ifndef _ILOG_H_
#define _ILOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if defined _MSC_VER
#	pragma warning(disable:4996)
#   if _MSC_VER > 1200     // vc6.0
#   define __func__ __FUNCTION__
#  else
#   define __func__ "<null>"	// 不支持__func__
#  endif
#endif

#define ILOG_ERROR_INTERNAL     -1000
#define ILOG_ERROR_OPEN         -1001
#define ILOG_ERROR_WRITE        -1002
#define ILOG_ERROR_PARAM        -1003
#define ILOG_ERROR_MEMORY       -1004
#define ILOG_ERROR_NOTSUPPORT   -1005

#define ILOG_INTERNAL_FORMAT	"--%3M-- %-7l **%S(%03L)**func:%-12F\n%f"	///< 内置的输出格式

typedef enum {
    LogLevelNull = 0,   ///< 不输出日志
    LogLevelDebug,      ///< 最详细的输出，debug时使用
    LogLevelInfo,       ///< 普通信息等级
    LogLevelNotice,     ///< 重要的信息
    LogLevelWarning,    ///< 警告信息
    LogLevelError,      ///< 错误信息
    LogLevelFatal       ///< 致命错误
} LogLevel;

typedef enum {
    LogTypeNull = 0,    ///< 不输出日志
    LogTypeFile,        ///< 输出到文件
    LogTypeStdout,      ///< 输出到stdout
    LogTypeStderr,      ///< 输出到stderr
    LogTypeSyslog,      ///< 输出到系统日志（syslog/Event Log)
    LogTypeCallback     ///< 用户自定义输出介质
} LogType;

typedef enum {
    LogStyleFormat,     ///< 使用格式化字符串
    LogStyleCallback    ///< 用户自定义输出方式
} LogStyle;

typedef enum {
    LogOptBufSize,      ///< 设置输出buf的大小
	LogOptOverWrite,    ///< 仅对输出到文件有效，是否覆盖日志文件
	LogOptInternalLog,  ///< 是否允许输出内部信息（提醒或者警告）
    LogOptRotateBySize, ///< 按日志大小进行日志转档
    LogOptRotateByDay,  ///< 日志每天转档
    LogOptRotateByHour  ///< 日志每小时转档
} LogOpt;

typedef struct {
    uint16_t year;
	uint8_t  mon;
	uint8_t  day;
    uint8_t  hour;
    uint8_t  min;
    uint8_t  sec;
    uint32_t usec;           // microsecond
} LogTime;

typedef struct {
    const char*	file;
    const char*	func;
    int			line;
} LogSource;

typedef struct _tag_ilog ilog;

/**
 * 用户自定义输出回调函数.
 * @param ctx: 传递给回调函数的参数
 * @param level: 日志等级
 * @param buf: 输出的内容
 * @param buflen: buf的大小
 * @return 实际写入的字节数
 */
typedef int (*LogOutputFunc)(void *ctx, LogLevel level, char *buf, int buflen);

/**
 * 用户自定义格式化输出.
 * @param ctx: 传递给回调函数的参数
 * @param buf: 输出字符串到buf
 * @param buflen: buf的大小
 * @return 格式化后的字符串长度
 */
typedef int (*LogStyleFunc)(void *ctx,
                            char *buf, int buflen,
                            LogLevel loglvl,
                            LogTime logtime,
                            LogSource logsrc,
                            unsigned long pid,
                            unsigned long tid,
                            const char *tag,
                            const char *text
                            );

/**
 * 初始化全局对象.
 * 可以不主动调用，使用其它函数时，如果未初始化，会自动调用。
 */
int ilogInit();

/**
 * 释放全局对象，应在程序结束时调用
 */
int ilogCleanup();

/**
 * 添加日志句柄到全局对象.
 * 一个句柄只能添加一次，多次添加会忽略
 * 如果是输出到文件，文件此时会创建，请在调用此函数前设置是否覆盖原日志文件
 * 如果未指定格式化输出方式，则使用内置的格式
 * 不提供遍历已添加的句柄的功能，用户应该在一个函数内完成日志初始化工作，因此不需要遍历
 * 不提供删除已添加的句柄的功能，如果需要，可以调用 ilogDestroy()
 * @see ilogDestroy(ilog *log)
 * @see ILOG_INTERNAL_FORMAT
 * @return 成功时返回0，否则返回非0值
 */
int ilogAddLog(ilog *log);

/**
 * 创建一个日志句柄.
 * 根据LogType来决定可变参数的作用
 * 输出到文件时，追加一个字符串参数，表示文件名
 * 输出到syslog时，追加一个字符串参数，表示ident
 * 输出到自定义回调函数时，追加两个参数，第一个是LogOutputFunc，第二个是传递给回调函数的参数
 * 其它情况不需要额外的参数
 */
ilog* ilogCreate(LogLevel level, LogType type, ...);

/**
 * 释放一个日志句柄.
 * @note 释放的时候，也会从全局对象中移除此句柄
 */
void ilogDestroy(ilog *log);

/**
 * 设置日志输出级别，大于等于此级别的日志才会输出.
 * log可以为空，此时对内置的日志句柄进行设置
 */
int ilogSetLevel(ilog *log, LogLevel level);

/**
 * 设置日志的输出方式.
 * log可以为空，此时对内置的日志句柄进行设置
 * 如果是将内置的句柄设置为输出到文件，将在此时创建文件
 * @see ilogCreate()
 */
int ilogSetOutputType(ilog *log, LogType type, ...);

/**
 * 一些额外的设置.
 * log可以为空，此时对内置的日志句柄进行设置
 * 需要一个额外的参数，1表示开启，0表示关闭
 * 如果设置按大小转档，额外的参数表示文件大小，0表示不转档
 * @see LogOpt
 */
int ilogSetOpt(ilog *log, LogOpt opt, ...);

/**
 * 设置此日志句柄的tag.
 * log可以为空，此时对内置的日志句柄进行设置
 */
int ilogSetTag(ilog *log, const char *tag);

/**
 * 设置日志的格式化方式.
 * 根据LogStyle来追加额外的参数
 * @see ilogSetStyleFormat()
 * @see ilogSetStyleCallback()
 */
int ilogSetStyle(ilog *log, LogStyle style, ...);

/**
 * 按照格式化字符串，用类似于printf的方式进行输出.
 * 转义序列：
 * %[-][width]type
 * '-'表示左对齐，否则右对齐
 * width表示输出宽度，输出的内容大于width时，无视width
 * type:
 * % '%'号本身
 * d 日期 YYYY-MM-DD
 * D 日期时间 YYYY-MM-DD HH:mm:ss
 * M 日期+精确时间（win32下精确到毫秒，unix下精确到微秒),宽度控制范围为0-6，表示精确到小数点后几位
 * l 日志等级
 * S 源码文件名
 * L 所在行数
 * F 所在函数
 * p pid
 * t tid
 * u 用户自定义tag
 * f 日志正文
 * log可以为空，此时对内置的日志句柄进行设置
 * @see ILOG_INTERNAL_FORMAT
 */
int ilogSetStyleFormat(ilog *log, const char *format);

/**
 * 设置格式输出的回调函数.
 * log可以为空，此时对内置的日志句柄进行设置
 * @see LogStyleFunc
 */
int ilogSetStyleCallback(ilog *log, LogStyleFunc func, void *ctx);

/**
 * 输出日志.
 */
int ilogWriteLog(LogLevel level,
				 const char *file, int line, const char *func,     // 源代码相关的信息
				 const char *format, ...);

/**
 * 输出日志，同时追加输出buf的信息.
 */
int ilogWriteHex(LogLevel level,
                 const char *file, int line, const char *func,  // 源代码相关的信息
                 void *buf, int len,
                 const char *format, ...);

/**
 * 返回日志等级对应的字符串.
 */
const char* ilogLevelToString(LogLevel level);

#define _log_internal(lvl, fmt, ...) \
                                ilogWriteLog((LogLevel)(lvl), __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define logDebug(fmt, ...)  _log_internal(LogLevelNull + 1, fmt, ##__VA_ARGS__)
#define logInfo(fmt, ...)   _log_internal(LogLevelNull + 2, fmt, ##__VA_ARGS__)
#define logNotice(fmt, ...) _log_internal(LogLevelNull + 3, fmt, ##__VA_ARGS__)
#define logWarn(fmt, ...)   _log_internal(LogLevelNull + 4, fmt, ##__VA_ARGS__)
#define logError(fmt, ...)  _log_internal(LogLevelNull + 5, fmt, ##__VA_ARGS__)
#define logFatal(fmt, ...)  _log_internal(LogLevelNull + 6, fmt, ##__VA_ARGS__)

#define _hexlog_internal(lvl, buf, len, fmt, ...) \
                                ilogWriteHex((LogLevel)(lvl), __FILE__, __LINE__, __func__, buf, len, fmt, ##__VA_ARGS__)
#define hexLogDebug(buf, len, fmt, ...)     _hexlog_internal(LogLevelNull + 1, buf, len, fmt, ##__VA_ARGS__)
#define hexLogInfo(buf, len, fmt, ...)      _hexlog_internal(LogLevelNull + 2, buf, len, fmt, ##__VA_ARGS__)
#define hexLogNotice(buf, len, fmt, ...)    _hexlog_internal(LogLevelNull + 3, buf, len, fmt, ##__VA_ARGS__)
#define hexLogWarn(buf, len, fmt, ...)      _hexlog_internal(LogLevelNull + 4, buf, len, fmt, ##__VA_ARGS__)
#define hexLogError(buf, len, fmt, ...)     _hexlog_internal(LogLevelNull + 5, buf, len, fmt, ##__VA_ARGS__)
#define hexLogFatal(buf, len, fmt, ...)     _hexlog_internal(LogLevelNull + 6, buf, len, fmt, ##__VA_ARGS__)

#define logIf(expr, level, fmt, ...) \
    do { \
        if(expr)\
			_log_internal(level, fmt, ##__VA_ARGS__); \
    } while(0);
#define hexLogIf(expr, level, buf, len, fmt, ...) \
    do { \
        if(expr)\
			_hexlog_internal(level, buf, len, fmt, ##__VA_ARGS__); \
    } while(0);

#ifdef __cplusplus
}
#endif

#endif // _ILOG_H_
