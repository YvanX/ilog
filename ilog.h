/*
 * ilog - log function libary in c
 * auther : YvanX
 * https://github.com/yvanx/ilog
 */

#ifndef _ILOG_H_
#define _ILOG_H_

#ifdef ILOG_EXPORT
#define ILOG_API __declspec(dllexport)
#else
#define ILOG_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if defined _MSC_VER
#	pragma warning(disable:4996)
#   if _MSC_VER > 1200     // vc6.0
#   define __func__ __FUNCTION__
#  else
#   define __func__ "<null>"	// ��֧��__func__
#  endif
#endif

#define ILOG_ERROR_INTERNAL     -1000
#define ILOG_ERROR_OPEN         -1001
#define ILOG_ERROR_WRITE        -1002
#define ILOG_ERROR_PARAM        -1003
#define ILOG_ERROR_MEMORY       -1004
#define ILOG_ERROR_NOTSUPPORT   -1005

#define ILOG_INTERNAL_FORMAT	"-%3M- | %7l | *%t %20S(%04L)@%F\n%f"	///< ���õ������ʽ

    typedef enum {
        LogLevelNull = 0,   ///< �������־
        LogLevelDebug,      ///< ����ϸ�������debugʱʹ��
        LogLevelInfo,       ///< ��ͨ��Ϣ�ȼ�
        LogLevelNotice,     ///< ��Ҫ����Ϣ
        LogLevelWarning,    ///< ������Ϣ
        LogLevelError,      ///< ������Ϣ
        LogLevelFatal       ///< ��������
    } LogLevel;

    typedef enum {
        LogTypeNull = 0,    ///< �������־
        LogTypeFile,        ///< ������ļ�
        LogTypeStdout,      ///< �����stdout
        LogTypeStderr,      ///< �����stderr
        LogTypeSyslog,      ///< �����ϵͳ��־��syslog/Event Log)
        LogTypeCallback     ///< �û��Զ����������
    } LogType;

    typedef enum {
        LogStyleFormat,     ///< ʹ�ø�ʽ���ַ���
        LogStyleCallback    ///< �û��Զ��������ʽ
    } LogStyle;

    typedef enum {
        LogOptSocket,		///< �����־��socket�������ڶ�̬��乲����ͬ�������ʽ�����������ͬһ�ļ�
        LogOptBufSize,      ///< �������buf�Ĵ�С
        LogOptOverWrite,    ///< ����������ļ���Ч���Ƿ񸲸���־�ļ�
        LogOptInternalLog,  ///< �Ƿ���������ڲ���Ϣ�����ѻ��߾��棩
        LogOptRotateBySize, ///< ����־��С������־ת��
        LogOptRotateByDay,  ///< ��־ÿ��ת��
        LogOptRotateByHour, ///< ��־ÿСʱת��
        LogOptRotateByTime  ///< ���ٷ��Ӻ�ת��
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
     * �û��Զ�������ص�����.
     * @param ctx: ���ݸ��ص������Ĳ���
     * @param level: ��־�ȼ�
     * @param buf: ���������
     * @param buflen: buf�Ĵ�С
     * @return ʵ��д����ֽ���
     */
    typedef int (*LogOutputFunc)(void *ctx, LogLevel level, char *buf, int buflen);

    /**
    * �û��Զ����ʽ�����.
    * @param ctx: ���ݸ��ص������Ĳ���
    * @param buf: ����ַ�����buf
    * @param buflen: buf�Ĵ�С
    * @return ��ʽ������ַ�������
    */
    typedef int(*LogStyleFunc)(void *ctx,
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
     * ��ʼ��ȫ�ֶ���.
     * ���Բ��������ã�ʹ����������ʱ�����δ��ʼ�������Զ����á�
     */
    ILOG_API int ilogInit();

    /**
     * �ͷ�ȫ�ֶ���Ӧ�ڳ������ʱ����
     */
    ILOG_API int ilogCleanup();

    /**
     * �����־�����ȫ�ֶ���.
     * һ�����ֻ�����һ�Σ������ӻ����
     * �����������ļ����ļ���ʱ�ᴴ�������ڵ��ô˺���ǰ�����Ƿ񸲸�ԭ��־�ļ�
     * ���δָ����ʽ�������ʽ����ʹ�����õĸ�ʽ
     * ���ṩ��������ӵľ���Ĺ��ܣ��û�Ӧ����һ�������������־��ʼ����������˲���Ҫ����
     * ���ṩɾ������ӵľ���Ĺ��ܣ������Ҫ�����Ե��� ilogDestroy()
     * @see ilogDestroy(ilog *log)
     * @see ILOG_INTERNAL_FORMAT
     * @return �ɹ�ʱ����0�����򷵻ط�0ֵ
     */
    ILOG_API int ilogAddLog(ilog *log);

    /**
     * ����һ����־���.
     * ����LogType�������ɱ����������
     * ������ļ�ʱ��׷��һ���ַ�����������ʾ�ļ���
     * �����syslogʱ��׷��һ���ַ�����������ʾident
     * ������Զ���ص�����ʱ��׷��������������һ����LogOutputFunc���ڶ����Ǵ��ݸ��ص������Ĳ���
     * �����������Ҫ����Ĳ���
     */
    ILOG_API ilog* ilogCreate(LogLevel level, LogType type, ...);

    /**
     * �ͷ�һ����־���.
     * @note �ͷŵ�ʱ��Ҳ���ȫ�ֶ������Ƴ��˾��
     */
    ILOG_API void ilogDestroy(ilog *log);

    /**
     * ������־������𣬴��ڵ��ڴ˼������־�Ż����.
     * log����Ϊ�գ���ʱ�����õ���־�����������
     */
    ILOG_API int ilogSetLevel(ilog *log, LogLevel level);

    /**
     * ������־�������ʽ.
     * log����Ϊ�գ���ʱ�����õ���־�����������
     * ����ǽ����õľ������Ϊ������ļ������ڴ�ʱ�����ļ�
     * @see ilogCreate()
     */
    ILOG_API int ilogSetOutputType(ilog *log, LogType type, ...);

    /**
     * һЩ���������.
     * log����Ϊ�գ���ʱ�����õ���־�����������
     * ��Ҫһ������Ĳ�����1��ʾ������0��ʾ�ر�
     * ������ð���Сת��������Ĳ�����ʾ�ļ���С��0��ʾ��ת��
     * @see LogOpt
     */
    ILOG_API int ilogSetOpt(ilog *log, LogOpt opt, ...);

    /**
     * ���ô���־�����tag.
     * log����Ϊ�գ���ʱ�����õ���־�����������
     */
    ILOG_API int ilogSetTag(ilog *log, const char *tag);

    /**
     * ������־�ĸ�ʽ����ʽ.
     * ����LogStyle��׷�Ӷ���Ĳ���
     * @see ilogSetStyleFormat()
     * @see ilogSetStyleCallback()
     */
    ILOG_API int ilogSetStyle(ilog *log, LogStyle style, ...);

    /**
     * ���ո�ʽ���ַ�������������printf�ķ�ʽ�������.
     * ת�����У�
     * %[-][width]type
     * '-'��ʾ����룬�����Ҷ���
     * width��ʾ�����ȣ���������ݴ���widthʱ������width
     * type:
     * % '%'�ű���
     * d ���� YYYY-MM-DD
     * D ����ʱ�� YYYY-MM-DD HH:mm:ss
     * M ����+��ȷʱ�䣨win32�¾�ȷ�����룬unix�¾�ȷ��΢��),��ȿ��Ʒ�ΧΪ0-6����ʾ��ȷ��С�����λ
     * l ��־�ȼ�
     * S Դ���ļ���
     * L ��������
     * F ���ں���
     * p pid
     * t tid
     * u �û��Զ���tag
     * f ��־����
     * log����Ϊ�գ���ʱ�����õ���־�����������
     * @see ILOG_INTERNAL_FORMAT
     */
    ILOG_API int ilogSetStyleFormat(ilog *log, const char *format);

    /**
     * ���ø�ʽ����Ļص�����.
     * log����Ϊ�գ���ʱ�����õ���־�����������
     * @see LogStyleFunc
     */
    ILOG_API int ilogSetStyleCallback(ilog *log, LogStyleFunc func, void *ctx);

    /**
     * �����־.
     */
    ILOG_API int ilogWriteLog(LogLevel level,
            const char *file, int line, const char *func,     // Դ������ص���Ϣ
            const char *format, ...);

    /**
     * �����־��ͬʱ׷�����buf����Ϣ.
     */
    ILOG_API int ilogWriteHex(LogLevel level,
            const char *file, int line, const char *func,  // Դ������ص���Ϣ
            void *buf, int len,
            const char *format, ...);

    /**
     * ������־�ȼ���Ӧ���ַ���.
     */
    ILOG_API const char* ilogLevelToString(LogLevel level);

    /**
     * ����socket�����������ڽ��ո���̬�ⷢ������־
     * @param port server�����Ķ˿ں�
     * @return 0 success <0 error
     */
    ILOG_API int ilogCreateServer(unsigned short port);

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
