#include "ilog.h"

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <math.h>

#if defined _WIN32
#include <WinSock2.h>
#include <windows.h>
#include <process.h>
#include <direct.h>
#include <io.h>
#define _ilog_os_win32
#elif defined __unix || defined __linux__ || defined __APPLE__
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#define _ilog_os_unix
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#if defined _ilog_os_unix
#define _strdup		strdup
#define _snprintf   snprintf
#define _vsnprintf  vsnprintf
#define _getpid     (unsigned long)getpid
#define _gettid     (unsigned long)gettid
#define _mkdir(name, mode)	mkdir(name, mode)
#define closesocket close
#define _chdir		chdir
#define _getcwd		getcwd
#define _access		access
#define ACCESS_EXIST	F_OK
#define HOMEPATH	"HOME"
#elif defined _ilog_os_win32
#define strtok_r    strtok_s
#define ioctl		ioctlsocket
#define _getpid     (unsigned long)GetCurrentProcessId
#define _gettid     (unsigned long)GetCurrentThreadId
#define _mkdir(name, mode)	mkdir(name)
#define ACCESS_EXIST	0
#define HOMEPATH	"USERPROFILE"
#ifndef __MINGW32__
typedef long mode_t;
#endif
#endif

#ifdef _WIN32
typedef int socklen_t;
#endif

#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#endif

#ifndef clamp
#define clamp(v, _min, _max)	min(max(_min, v), _max)
#endif

#ifndef MAX_PATH
#define MAX_PATH 250
#endif

#define ABS(n)	(n >= 0 ? n : -n)

typedef struct _tag_format_list {
    void *attr;
    int width;
    int fill;
    struct _tag_format_list *next;
} LogFormatList;

struct _tag_ilog {
    LogLevel    level;
    LogType     type;
    char		tag[32];
    uint8_t		overwrite;				// 是否覆盖原日志文件
    uint32_t	rotateTime;			    // 0: 不转档  >0: 多少分钟后转档
    uint32_t	rotateSize;				// 按大小转档
    uint8_t     internalLog;			// 是否允许输出内部信息
    const char*	fileName;
    FILE*		logFile;
    time_t      backupTime;
    int         backupNum;
    void*		ctx;
    LogStyleFunc	styleFunc;
    LogOutputFunc	outputFunc;
    LogFormatList	*formatList;
#if defined _ilog_os_win32
    HANDLE		syslog;
#endif
};

typedef struct _tag_log_node {
    ilog *log;
    struct _tag_log_node *next;
} LogList;

typedef struct _tag_ilogs {
    LogList		*logList;
    ilog		*internalLog;			// 如果logList为空，则输出到此日志句柄
    char		*outBuf;
    char        *txtBuf;                // snprintf 输出到这里，避免反复的申请内存
    uint32_t	outBufSize;
    int			socket;
    int			isServerRunning;
#if defined _ilog_os_unix
    int			syslogFlag;
    pthread_mutex_t mtxTxt;
    pthread_mutex_t mtxClient;
    pthread_mutex_t mtxServer;
    pthread_t threadServer;
#elif defined _ilog_os_win32
    HANDLE mtxTxt;
    HANDLE mtxClient;
    HANDLE mtxServer;
    HANDLE threadServer;
#endif
} ilogManager;

static ilogManager *ilogMgr = NULL;

static int ilogConnect(unsigned short port);
static int ilogSend(int sock, int hexSize, LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *txt);
static int ilogSendHex(int sock, void *buf, int len);

#ifdef _ilog_os_unix
static pid_t gettid()
{
#ifdef __APPLE__
    return syscall(SYS_thread_selfid);
#else
    return syscall(SYS_gettid);
#endif
}
#endif

static void normalizePath(char *path)
{
    int i;
    for(i = strlen(path); i >= 0; i--) {
        if(path[i] == '\\')
            path[i] = '/';
    }
}

static int mkdir_r(const char *name, mode_t mode)
{
    int ret;
    char *pwd;
    char *ptr;
    char *path;
    char buf[260];
    if(!name || name[0] == '\0')
        return -1;
    pwd = _getcwd(NULL, 0);
    ptr = path = _strdup(name);
    normalizePath(path);
    if(path[0] == '/') {
        ret = _chdir("/");
        if(ret == -1) {
            perror("chdir");
        }
        ptr++;
    } else if(path[0] == '~') {
        char *home;
        home = getenv(HOMEPATH);
        ret = _chdir(home);
        if(ret == -1) {
            perror("chdir");
        }
        ptr += 2;
    }

    while(*ptr != '\0') {
        int i;
        for(i = 0; (*ptr != '/' && *ptr != '\0') || (*ptr == '/' && i > 0 && *(ptr - 1) == ':'); ptr++) {
            buf[i++] = *ptr;
        }
        buf[i] = '\0';

        if(_access(buf, ACCESS_EXIST) == -1) {
            ret = _mkdir(buf, mode);
            if(ret == -1) {
                perror("mkdir");
                break;
            }
            _chdir(buf);
        } else {
            ret = _chdir(buf);
            if(ret == -1) {
                perror("chdir");
                break;
            }
        }
        if(*ptr == '\0') {
            break;
        }
        ptr++;
    }
    _chdir(pwd);
    free(path);
    free(pwd);
    return 0;
}

static FILE* createFile(const char *name, const char *mode)
{
    char *tmp;
    char *path;
    FILE *file;

    if(name == NULL) {
        return NULL;
    }

    path = _strdup(name);
    normalizePath(path);
    tmp = strrchr(path, '/');
    if(tmp) {
        *tmp = '\0';
        mkdir_r(path, 0777);
    }
    free(path);

    path = (char*)malloc(MAX_PATH);
    if(name[0] == '~') {
        _snprintf(path, MAX_PATH, "%s/%s", getenv(HOMEPATH), name + 2);
    } else {
        _snprintf(path, MAX_PATH, "%s", name);
    }
    file = fopen(path, mode);
    free(path);
    return file;
}

static LogTime getCurrentTime()
{
    LogTime t;
#ifdef _ilog_os_unix
    struct tm tb;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    localtime_r((time_t*)&tv.tv_sec, &tb);
    t.year = tb.tm_year + 1900;
    t.mon = tb.tm_mon + 1;
    t.day = tb.tm_mday;
    t.hour = tb.tm_hour;
    t.min = tb.tm_min;
    t.sec = tb.tm_sec;
    t.usec = tv.tv_usec;
#elif defined _ilog_os_win32
    SYSTEMTIME now;

    GetLocalTime(&now);
    t.year = (uint16_t)now.wYear;
    t.mon = (uint8_t)now.wMonth;
    t.day = (uint8_t)now.wDay;
    t.hour = (uint8_t)now.wHour;
    t.min = (uint8_t)now.wMinute;
    t.sec = (uint8_t)now.wSecond;
    t.usec = (uint32_t)now.wMilliseconds * 1000;
#endif

    return t;
}

typedef enum {
    FormatDate = 0,			// %d
    FormatDatetime,			// %D
    FormatDatetimems,		// %M
    FormatLoglevel,			// %l
    FormatSource,			// %S
    FormatLine,				// %L
    FormatFunction,			// %F
    FormatPid,				// %p
    FormatTid,				// %t
    FormatTag,				// %u
    FormatText,				// %f
    FormatTagEnd
} FormatAttr;

typedef enum _tag_format_status {
    StatusStart, StatusEscape, StatusAlign, StatusNumber, StatusAttr
} formatStatus;

#define bufferReset() \
    offset = 0; \
memset(buf, 0, sizeof(buf));

static int checkSpecifier(char c)
{
    int i;
    static const char *attr = "dDMlSLFptuf";
    for(i = 0; i < 11; i++) {
        if(c == attr[i]) {
            return i;
        }
    }
    return -1;
}

static LogFormatList* parseFormat(const char *str)
{
    int i;
    int len;

    int spec;
    int fill;
    int offset;
    char buf[256];
    formatStatus status;
    int timeflag = 0;		// %d %D %M 不能同时使用

    LogFormatList *head, *tail;
    LogFormatList *tmp;
    head = tail = tmp = NULL;
    if(!str) {
        return head;
    }
    len = strlen(str);
    if(len == 0 || len > 256) {
        return head;
    }

    fill = 0;
    spec = -1;
    status = StatusStart;
    bufferReset();
    for(i = 0; i < len; i++) {
        char c = str[i];
        if(status == StatusStart) {
            if(c == '%') {
                if(str[i + 1] == '%') {
                    i++;
                    buf[offset++] = c;
                    continue;
                }
                fill = 0;
                status = StatusEscape;
                if(offset == 0)
                    continue;
            } else {
                buf[offset++] = c;
                continue;
            }
        } else if(status == StatusEscape) {
            if(c == '-') {
                bufferReset();
                status = StatusAlign;
                buf[offset++] = c;
                continue;
            } else if(c == '0') {
                fill = 1;
                bufferReset();
                status = StatusNumber;
                continue;
            } else if(c > '0' && c <= '9') {
                bufferReset();
                status = StatusNumber;
                buf[offset++] = c;
                continue;
            } else {
                status = StatusStart;
                spec = checkSpecifier(c);
                if(spec >= FormatDate && spec <= FormatDatetimems) {
                    if(timeflag == 0) {
                        timeflag = 1;
                    } else {
                        printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
                        bufferReset();
                        continue;
                    }
                }
                if(spec == -1) {
                    printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
                    bufferReset();
                    continue;
                }
            }
        } else if(status == StatusAlign) {
            if(c == '0') {
                fill = 1;
                status = StatusNumber;
                continue;
            } else if(c > '0' && c <= '9') {
                status = StatusNumber;
                buf[offset++] = c;
                continue;
            } else {
                status = StatusStart;
                spec = checkSpecifier(c);
                if(spec >= FormatDate && spec <= FormatDatetimems) {
                    if(timeflag == 0) {
                        timeflag = 1;
                    } else {
                        printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
                        bufferReset();
                        continue;
                    }
                }
                if(spec == -1) {
                    printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
                    bufferReset();
                    continue;

                }
            }
        } else if(status == StatusNumber) {
            if(c >= '0' && c <= '9') {
                buf[offset++] = c;
                continue;
            } else {
                status = StatusStart;
                spec = checkSpecifier(c);
                if(spec >= FormatDate && spec <= FormatDatetimems) {
                    if(timeflag == 0) {
                        timeflag = 1;
                    } else {
                        printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
                        bufferReset();
                        continue;
                    }
                }
                if(spec == -1) {
                    printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
                    bufferReset();
                    continue;
                }
            }
        }

        tmp = (LogFormatList*)malloc(sizeof(LogFormatList));
        if(spec == -1) {
            tmp->attr = (void*)_strdup(buf);
        } else {
            int width = atoi(buf);
            int sign = width >= 0 ? 1 : -1;
            if(spec == FormatDatetimems) {
                sign = 1;
                width = clamp(ABS(width), 0, 6);
            } else if(spec == FormatSource) {
                width = clamp(ABS(width), 0, MAX_PATH);
            } else if(spec == FormatLine || spec == FormatPid || spec == FormatTid) {
                if(fill) sign = 1;		// 如果使用0填充，则不能使用左对齐
                width = clamp(ABS(width), 0, 16);
            } else if(spec == FormatFunction) {
                width = clamp(ABS(width), 0, 64);
            } else {
                width = clamp(ABS(width), 0, 32);
            }
            tmp->attr = (void*)(long)spec;
            tmp->fill = fill;
            tmp->width = sign * width;
        }
        tmp->next = NULL;
        if(tail != NULL) {
            tail->next = tmp;
            tail = tmp;
        } else {
            head = tmp;
            tail = tmp;
        }
        spec = -1;
        offset = 0;
        memset(buf, 0, sizeof(buf));
    }

    return head;
}

static void releaseFormat(LogFormatList *fmt)
{
    LogFormatList *tmp;
    while(fmt) {
        if((long)fmt->attr > FormatTagEnd) {
            free(fmt->attr);
        }
        tmp = fmt;
        fmt = fmt->next;
        free(tmp);
    }
}

static int ilogOpenSyslog(ilog *log)
{
    if(!log || !log->fileName) {
        return ILOG_ERROR_PARAM;
    }
#if defined _ilog_os_unix
    ilogMgr->syslogFlag = 1;
    openlog(log->fileName, LOG_PID, LOG_USER);
#elif defined _ilog_os_win32
    if(!log->syslog) {
        log->syslog = RegisterEventSourceA(NULL, log->fileName);
    }
#endif
    return 0;
}

static int ilogWriteSyslog(ilog *log, LogLevel level, char *buf, int buflen)
{
#if defined _ilog_os_unix
    int	syslogLevel;
    switch(level) {
    case LogLevelDebug:
        syslogLevel = LOG_DEBUG;
        break;
    case LogLevelInfo:
        syslogLevel = LOG_INFO;
        break;
    case LogLevelNotice:
        syslogLevel = LOG_NOTICE;
        break;
    case LogLevelWarning:
        syslogLevel = LOG_WARNING;
        break;
    case LogLevelError:
        syslogLevel = LOG_ERR;
        break;
    case LogLevelFatal:
        syslogLevel = LOG_CRIT;
        break;
    default:
        syslogLevel = LOG_DEBUG;
        break;
    }
    syslog(syslogLevel, buf);
#elif defined _ilog_os_win32
    unsigned short syslogLevel;
    if(!log || !log->syslog) {
        return ILOG_ERROR_PARAM;
    }
    if(level == LogLevelDebug || level == LogLevelInfo || level == LogLevelNotice)
        syslogLevel = EVENTLOG_INFORMATION_TYPE;
    else if(level == LogLevelWarning)
        syslogLevel = EVENTLOG_WARNING_TYPE;
    else if(level == LogLevelError || level == LogLevelFatal)
        syslogLevel = EVENTLOG_ERROR_TYPE;
    else
        syslogLevel = EVENTLOG_INFORMATION_TYPE;
    ReportEventA(log->syslog, syslogLevel, 0, 0, NULL, 1, 0, (const char**)&buf, NULL);
#endif
    return 0;
}

static int ilogCloseSyslog(ilog *log)
{
#if defined _ilog_os_unix
    if(ilogMgr && ilogMgr->syslogFlag == 1) {
        ilogMgr->syslogFlag = 0;
        closelog();
    }
#elif defined _ilog_os_win32
    if(log->syslog) {
        DeregisterEventSource(log->syslog);
        log->syslog = NULL;
    }
#endif
    return 0;
}

static void ilogRelease(ilog *log)
{
    if(!log) {
        return;
    }
    if(log->logFile) {
        fclose(log->logFile);
    }
    if(log->fileName) {
        free((void*)log->fileName);
    }
    if(log->formatList) {
        releaseFormat(log->formatList);
    }
    ilogCloseSyslog(log);

    free(log);
}

#if defined _ilog_os_unix

static void ilogMutexLock(pthread_mutex_t *mutex)
{
    pthread_mutex_lock(mutex);
}

static void ilogMutexUnlock(pthread_mutex_t *mutex)
{
#if defined _ilog_os_unix
    pthread_mutex_unlock(mutex);
#elif defined _ilog_os_win32
#endif
}
#elif defined _ilog_os_win32

static void ilogMutexLock(HANDLE *mutex)
{
    WaitForSingleObject(*mutex, INFINITE);
}

static void ilogMutexUnlock(HANDLE *mutex)
{
    ReleaseMutex(*mutex);
}
#endif

ILOG_API int ilogInit()
{
    ilog *internalLog;
    if(ilogMgr) {
        return 0;
    }

    ilogMgr = (ilogManager*)malloc(sizeof(ilogManager));
    if(!ilogMgr) {
        return ILOG_ERROR_MEMORY;
    }
    ilogMgr->logList = NULL;
    ilogMgr->outBufSize = 2 * 1024;			// 2K
    ilogMgr->socket = -1;
    ilogMgr->isServerRunning = 0;
    ilogMgr->outBuf = (char*)malloc(ilogMgr->outBufSize);
    ilogMgr->txtBuf = (char*)malloc(ilogMgr->outBufSize);
    if(!ilogMgr->outBuf || !ilogMgr->txtBuf) {
        return ILOG_ERROR_MEMORY;
    }

    internalLog = ilogCreate(LogLevelDebug, LogTypeStdout);
    if(!internalLog) {
        return ILOG_ERROR_INTERNAL;
    }
    ilogSetStyle(internalLog, LogStyleFormat, ILOG_INTERNAL_FORMAT);
    ilogMgr->internalLog = internalLog;

#if defined _ilog_os_unix
    ilogMgr->syslogFlag = 0;
    pthread_mutex_init(&ilogMgr->mtxTxt, NULL);
    pthread_mutex_init(&ilogMgr->mtxClient, NULL);
    pthread_mutex_init(&ilogMgr->mtxServer, NULL);
    ilogMgr->threadServer = 0;
#elif defined _ilog_os_win32
    ilogMgr->mtxTxt = CreateMutex(NULL, FALSE, NULL);
    ilogMgr->mtxClient = CreateMutex(NULL, FALSE, NULL);
    ilogMgr->mtxServer = CreateMutex(NULL, FALSE, NULL);
    ilogMgr->threadServer = NULL;
#endif
    return 0;
}

ILOG_API int ilogCleanup()
{
    if(!ilogMgr) {
        return 0;
    }

    if(ilogMgr->isServerRunning) {
        ilogMutexLock(&ilogMgr->mtxServer);
        ilogMutexUnlock(&ilogMgr->mtxServer);
#ifdef _ilog_os_unix
        usleep(50000);
#elif defined _ilog_os_win32
        Sleep(50);
#endif
        ilogMgr->isServerRunning = 0;
#ifdef _ilog_os_unix
        pthread_join(ilogMgr->threadServer, NULL);
#elif defined _ilog_os_win32
        WaitForSingleObject(ilogMgr->threadServer, INFINITE);
#endif
    }

    if(ilogMgr->socket >= 0) {
        closesocket(ilogMgr->socket);
    }

    while(ilogMgr->logList) {
        LogList *node = ilogMgr->logList;
        ilogMgr->logList = node->next;
        ilogRelease(node->log);
        free(node);
    }
    ilogRelease(ilogMgr->internalLog);
    free(ilogMgr->outBuf);
    free(ilogMgr->txtBuf);

#if defined _ilog_os_unix
    pthread_mutex_destroy(&ilogMgr->mtxTxt);
    pthread_mutex_destroy(&ilogMgr->mtxClient);
    pthread_mutex_destroy(&ilogMgr->mtxServer);
#elif defined _ilog_os_win32
    CloseHandle(ilogMgr->mtxTxt);
    CloseHandle(ilogMgr->mtxClient);
    CloseHandle(ilogMgr->mtxServer);
#endif

    free(ilogMgr);
    ilogMgr = NULL;
    return 0;
}

ILOG_API int ilogAddLog(ilog *log)
{
    LogList *node, *tail;
    if(!log) {
        return ILOG_ERROR_PARAM;
    }
    if(!ilogMgr) {
        ilogInit();
    }
    if(!ilogMgr) {
        return ILOG_ERROR_INTERNAL;
    }

    tail = ilogMgr->logList;
    while(tail) {
        if(tail->log == log) {
            return ILOG_ERROR_PARAM;
        }
        if(tail->next) {
            tail = tail->next;
        } else {
            break;
        }
    }

    node = (LogList*)malloc(sizeof(LogList));
    if(!node) {
        return ILOG_ERROR_MEMORY;
    }
    node->log = log;
    node->next = NULL;
    if(tail) {
        tail->next = node;
    } else {
        ilogMgr->logList = node;
    }

    if(!log->styleFunc && !log->formatList) {
        ilogSetStyle(log, LogStyleFormat, ILOG_INTERNAL_FORMAT);
    }

    if(log->type == LogTypeFile && log->fileName) {
        if(log->overwrite == 0) {
            log->logFile = createFile(log->fileName, "at");
        } else {
            log->logFile = createFile(log->fileName, "wt");
        }
    } else if(log->type == LogTypeSyslog && log->fileName) {
        ilogOpenSyslog(log);
    }
    return 0;
}

ILOG_API ilog* ilogCreate(LogLevel level, LogType type, ...)
{
    ilog *log;
    log = (ilog*)malloc(sizeof(ilog));
    if(!log) {
        return NULL;
    }
    log->level = level;
    log->type = type;
    memset(log->tag, 0, sizeof(log->tag));
    log->overwrite = 0;
    log->rotateSize = 0;
    log->rotateTime = 0;
    log->internalLog = 1;
    log->logFile = NULL;
    log->fileName = NULL;
    log->backupTime = 0;
    log->backupNum = 0;
    log->ctx = NULL;
    log->formatList = NULL;
    log->styleFunc = NULL;
    log->outputFunc = NULL;

    if(type == LogTypeFile) {
        va_list va;
        va_start(va, type);
        log->fileName = _strdup(va_arg(va, char*));
        va_end(va);
    } else if(type == LogTypeSyslog) {
        va_list va;
        va_start(va, type);
        log->fileName = _strdup(va_arg(va, char*));
        va_end(va);
    } else if(type == LogTypeCallback) {
        va_list va;
        va_start(va, type);
        log->outputFunc = va_arg(va, LogOutputFunc);
        log->ctx = va_arg(va, void*);
        va_end(va);
    }
#if defined _ilog_os_win32
    log->syslog = NULL;
#endif

    return log;
}

ILOG_API void ilogDestroy(ilog *log)
{
    LogList *node;
    if(!log || !ilogMgr) {
        return;
    }

    node = ilogMgr->logList;
    // 删除头节点
    if(log == node->log) {
        ilogMgr->logList = node->next;
        ilogRelease(log);
        free(node);
        return;
    }

    while(node) {
        if(node->next && node->next->log == log) {
            LogList *tmp = node->next;
            node->next = tmp->next;
            ilogRelease(log);
            free(tmp);
            return;
        }
        node = node->next;
    }
}

ILOG_API int ilogSetLevel(ilog *log, LogLevel level)
{
    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }
    log->level = level;
    return 0;
}

ILOG_API int ilogSetOutputType(ilog *log, LogType type, ...)
{
    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }

    log->type = type;
    if(type == LogTypeFile) {
        va_list va;
        if(log->fileName) {
            free((void*)log->fileName);
        }
        va_start(va, type);
        log->fileName = _strdup(va_arg(va, char*));
        va_end(va);
        if(log == ilogMgr->internalLog) {
            if(log->logFile) {
                fclose(log->logFile);
            }
            if(log->overwrite == 0) {
                log->logFile = createFile(log->fileName, "at");
            } else {
                log->logFile = createFile(log->fileName, "wt");
            }
        }
    } else if(type == LogTypeSyslog) {
        va_list va;
        if(log->fileName) {
            free((void*)log->fileName);
        }
        va_start(va, type);
        log->fileName = _strdup(va_arg(va, char*));
        va_end(va);
        if(log == ilogMgr->internalLog) {
            ilogOpenSyslog(log);
        }
    } else if(type == LogTypeCallback) {
        va_list va;
        va_start(va, type);
        log->outputFunc = va_arg(va, LogOutputFunc);
        log->ctx = va_arg(va, void*);
        va_end(va);
    }
    return 0;
}

ILOG_API int ilogSetOpt(ilog *log, LogOpt opt, ...)
{
    va_list va;
    uint32_t value;

    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }

    va_start(va, opt);
    value = va_arg(va, uint32_t);
    va_end(va);
    switch(opt) {
    case LogOptSocket:
        if(ilogMgr->socket > 0) {
            closesocket(ilogMgr->socket);
        }
        ilogMgr->socket = ilogConnect((unsigned short)value);
        break;
    case LogOptBufSize:
        ilogMgr->outBufSize = value;
        ilogMgr->outBuf = (char*)realloc(ilogMgr->outBuf, value);
        ilogMgr->txtBuf = (char*)realloc(ilogMgr->txtBuf, value);
        break;
    case LogOptOverWrite:
        log->overwrite = (value != 0);
        break;
    case LogOptInternalLog:
        log->internalLog = (value != 0);
        break;
    case LogOptRotateBySize:
        log->rotateSize = value;
        break;
    case LogOptRotateByHour:
        if(value != 0) {
            log->rotateTime = 60;
            log->backupTime = time(NULL) + 3600;
        } else {
            log->rotateTime = 0;
        }
        break;
    case LogOptRotateByDay:
        if(value != 0) {
            log->rotateTime = 1440;
            log->backupTime = time(NULL) + 1440 * 60;
        } else {
            log->rotateTime = 0;
        }
        break;
    case LogOptRotateByTime:
        log->rotateTime = value;
        log->backupTime = time(NULL) + 60 * value;
        break;
    default:
        break;
    }
    return 0;
}

ILOG_API int ilogSetTag(ilog *log, const char *tag)
{
    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }
    if(!tag) {
        return ILOG_ERROR_PARAM;
    }
    _snprintf(log->tag, sizeof(log->tag), "%s", tag);
    return 0;
}

ILOG_API int ilogSetStyle(ilog *log, LogStyle style, ...)
{
    va_list va;
    va_start(va, style);
    if(style == LogStyleFormat) {
        char *format = va_arg(va, char*);
        va_end(va);
        return ilogSetStyleFormat(log, format);
    } else if(style == LogStyleCallback) {
        LogStyleFunc func = va_arg(va, LogStyleFunc);
        void *ctx = va_arg(va, void*);
        va_end(va);
        return ilogSetStyleCallback(log, func, ctx);
    } else {
        return ILOG_ERROR_PARAM;
    }
}

ILOG_API int ilogSetStyleFormat(ilog *log, const char *format)
{
    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }
    log->styleFunc = NULL;
    log->ctx = NULL;
    if(log->formatList) {
        releaseFormat(log->formatList);
    }
    log->formatList = parseFormat(format);
    if(!log->formatList) {
        return ILOG_ERROR_PARAM;
    }
    return 0;
}

ILOG_API int ilogSetStyleCallback(ilog *log, LogStyleFunc func, void *ctx)
{
    if(!ilogMgr) {
        ilogInit();
    }
    if(!log) {
        log = ilogMgr->internalLog;
    }
    log->styleFunc = func;
    log->ctx = ctx;
    return 0;
}

static int textAlign(char *buf, const char *str, int width, char fill)
{
    int len = strlen(str);
    int align = width < 0 ? 0 : 1;
    width = ABS(width);
    if(len >= width) {
        strcpy(buf, str);
        return len;
    } else {
        if(align == 0) {
            strcpy(buf, str);
            memset(buf + len, fill, width - len);
            buf[width] = '\0';
        } else if(align == 1) {
            memset(buf, fill, width - len);
            strcpy(buf + width - len, str);
        }
        return width;
    }
}

static const char *getBaseName(const char *name)
{
    int i;
    for(i = strlen(name); i >= 0; i--) {
        if(name[i] == '/' || name[i] == '\\') {
            return name + i + 1;
        }
    }
    return name;
}

#define MoveBufPtr(buf, offset, remain) \
    buf += offset; \
remain -= offset;

static int ilogFormamt(ilog *log, char *buf, int buflen, LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *tag, const char *txt)
{
    int len;
    int need;
    char tmp[256];
    char number[16];
    char* const ptr = buf;
    LogFormatList *fmt;

    if(!log || !log->formatList) {
        return 0;
    }
    fmt = log->formatList;

    while(fmt && buflen > 0) {
        if((long)fmt->attr < FormatTagEnd) {
            FormatAttr spec = (FormatAttr)(long)fmt->attr;
            switch(spec) {
            case FormatDate:
                len = _snprintf(buf, buflen, "%04d-%02d-%02d", time.year, time.mon, time.day);
                MoveBufPtr(buf, len, buflen);
                break;
            case FormatDatetime:
                len = _snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d", time.year, time.mon, time.day, time.hour, time.min, time.sec);
                MoveBufPtr(buf, len, buflen);
                break;
            case FormatDatetimems:
                len = _snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d", time.year, time.mon, time.day, time.hour, time.min, time.sec);
                MoveBufPtr(buf, len, buflen);
                if(fmt->width == 0 || fmt->width >= 6) {
                    need = 6 + 1;       // width + '.' + '\0'
                } else {
                    need = fmt->width + 1;
                }
                if(buflen <= need) {
                    break;
                }
                len = _snprintf(buf, buflen, ".%06d", time.usec);
                MoveBufPtr(buf, need, buflen);
                break;
            case FormatLoglevel:
                if(fmt->width == 0) {
                    len = _snprintf(buf, buflen, "%s", ilogLevelToString(level));
                    MoveBufPtr(buf, len, buflen);
                } else {
                    textAlign(tmp, ilogLevelToString(level), fmt->width, ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatSource:
                src.file = getBaseName(src.file);
                if(fmt->width == 0) {
                    len = _snprintf(buf, buflen, "%s", src.file);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    textAlign(tmp, src.file, fmt->width, ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatLine:
                _snprintf(number, 16, "%d", src.line);
                if(fmt->width != 0) {
                    textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    len = _snprintf(buf, buflen, "%s", number);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatFunction:
                if(fmt->width == 0) {
                    len = _snprintf(buf, buflen, "%s", src.func);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    textAlign(tmp, src.func, fmt->width, ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatPid:
                _snprintf(number, 16, "%ld", pid);
                if(fmt->width != 0) {
                    textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    len = _snprintf(buf, buflen, "%s", number);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatTid:
                _snprintf(number, 16, "%ld", tid);
                if(fmt->width != 0) {
                    textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    len = _snprintf(buf, buflen, "%s", number);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatTag:
                if(!tag) {
                    tag = "<no tag>";
                }
                if(fmt->width == 0) {
                    len = _snprintf(buf, buflen, "%s", tag);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    textAlign(tmp, tag, fmt->width, ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            case FormatText:
                if(fmt->width == 0) {
                    len = _snprintf(buf, buflen, "%s", txt);
                    MoveBufPtr(buf, len, buflen);
                } else {
                    textAlign(tmp, txt, fmt->width, ' ');
                    len = _snprintf(buf, buflen, "%s", tmp);
                    MoveBufPtr(buf, len, buflen);
                }
                break;
            default:
                break;
            }
        } else {
            const char *txt = (char*)fmt->attr;
            len = _snprintf(buf, buflen, "%s", txt);
            MoveBufPtr(buf, len, buflen);
        }
        fmt = fmt->next;
    }
    len = _snprintf(buf, buflen, "\n");
    MoveBufPtr(buf, len, buflen);
    if(buflen < 0) {
        buf += buflen;      // 返回设置的缓冲区大小
    }
    return buf - ptr;
}

static const char* ilogBackupPath(const char *oldPath, char *path, int hasTime, int number)
{
    int offset;
    char *suffix;
    char temp[16];
    LogTime t;

    suffix = strrchr(oldPath, '.');
    if(suffix) {
        offset = suffix - oldPath;
        strncpy(path, oldPath, suffix - oldPath);
        path[suffix - oldPath] = '\0';
    } else {
        offset = strlen(oldPath);
        strcpy(path, oldPath);
    }

    if(hasTime) {
        t = getCurrentTime();
        int ret = _snprintf(temp, sizeof(temp), "%4d%02d%02d-%02d%02d", t.year, t.mon, t.day, t.hour, t.min);
        strcpy(path + offset, temp);
        offset += ret;
    }

    if(number != 0) {
        int ret = _snprintf(temp, sizeof(temp), "_%02d", number);
        strcpy(path + offset, temp);
        offset += ret;
    }

    if(suffix) {
        strcpy(path + offset, suffix);
    }

    return path;
}

static void ilogCheckBackup(ilog *log)
{
    int number = 0;
    int hasTime = 0;
    int needBack = 0;
    char backupPath[MAX_PATH];
    size_t len = ftell(log->logFile);
    hasTime = log->rotateTime != 0;
    if(log->rotateSize > 0 && len > log->rotateSize) {
        log->backupNum++;
        number = log->backupNum;
        needBack = 1;
    }
    if(log->rotateTime != 0 && time(NULL) > log->backupTime) {
        log->backupTime = time(NULL);
        log->backupTime += 60 * log->rotateTime;
        log->backupNum = 0;
        needBack = 1;
    }
    if(needBack) {
        ilogBackupPath(log->fileName, backupPath, hasTime, number);
        fclose(log->logFile);
        rename(log->fileName, backupPath);
        log->logFile = fopen(log->fileName, "wt");
    }
    return;
}

static int ilogOutput(ilog *log, LogLevel level, char *buf, int len)
{
    int ret;
    if(len == 0 || !log || !buf) {
        return 0;
    }
    if(log->level == LogLevelNull) {
        return 0;
    }
    switch(log->type) {
    case LogTypeStdout:
        fwrite(buf, len, 1, stdout);
        break;
    case LogTypeStderr:
        fwrite(buf, len, 1, stderr);
        break;
    case LogTypeFile:
        if(log->logFile) {
            fwrite(buf, len, 1, log->logFile);
            fflush(log->logFile);
            ilogCheckBackup(log);
        }
        break;
    case LogTypeSyslog:
        ilogWriteSyslog(log, level, buf, len);
        break;
    case LogTypeCallback:
        if(log->outputFunc) {
            ret = log->outputFunc(log->ctx, level, buf, len);
            if(ret != len) {
                // 
            }
        }
    default:
        break;
    }
    return 0;
}

static int ilogWriteHexBase(char *output, int outSize, void *buf, int inSize, int *processed, int base)
{
    int i;
    int ret;
    int bytesLeft;
    int offset;
    char *ptr;

    offset = 0;
    ptr = output;

    while(offset < inSize) {
        int end;
        bytesLeft = min(inSize - offset, 16);
        end = offset + bytesLeft;
        ret = _snprintf(ptr, outSize, "0x%08X   ", offset + base);
        MoveBufPtr(ptr, ret, outSize);
        for(i = offset; i < end; i++) {
            ret = _snprintf(ptr, outSize, " %02X", ((unsigned char*)buf)[i]);
            MoveBufPtr(ptr, ret, outSize);
        }
        for(i = 16 - bytesLeft; i > 0; i--) {
            ret = _snprintf(ptr, outSize, "   ");
            MoveBufPtr(ptr, ret, outSize);
        }
        ret = _snprintf(ptr, outSize, "  ");
        MoveBufPtr(ptr, ret, outSize);
        for(i = offset; i < end; i++) {
            unsigned char c = ((unsigned char*)buf)[i];
            if(isprint(c) || c >= 0x80) {
                *ptr++ = c;
                outSize--;
            } else {
                *ptr++ = '.';
                outSize--;
            }
        }
        *ptr++ = '\n';
        outSize--;
        offset = end;
        if(outSize <= 80) {
            break;
        }
    }
    *ptr = '\0';
    *processed = offset;
    return ptr - output;
}

static int ilogWriteLogBase(ilog *log, LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *txt)
{
    int len;
    if(!log) {
        return ILOG_ERROR_PARAM;
    }
    if(log->level > level || log->level == LogLevelNull || log->type == LogTypeNull) {
        return 0;
    }
    if(!log->styleFunc) {
        len = ilogFormamt(log, ilogMgr->outBuf, ilogMgr->outBufSize, level, time, src, pid, tid, log->tag, txt);
    } else {
        len = log->styleFunc(log->ctx, ilogMgr->outBuf, ilogMgr->outBufSize, level, time, src, pid, tid, log->tag, txt);
    }
    ilogOutput(log, level, ilogMgr->outBuf, len);
    return 0;
}

static int ilogWriteToHandle(LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *txt)
{
    ilog *log;
    LogList *node;
    if(!ilogMgr->logList) {
        log = ilogMgr->internalLog;
        ilogWriteLogBase(log, level, time, src, pid, tid, txt);
        return 0;
    }

    node = ilogMgr->logList;
    while(node) {
        ilogWriteLogBase(node->log, level, time, src, pid, tid, txt);
        node = node->next;
    }
    return 0;
}

static int ilogWriteHexToHandle(LogLevel level, void *buf, int size, int base)
{
    ilog *log;
    LogList *node;
    char output[8192];
    int offset = 0;

    while(offset < size) {
        int len;
        int processed;
        len = ilogWriteHexBase(output, sizeof(output), (char*)buf + offset, size - offset, &processed, base + offset);
        offset += processed;
        if(!ilogMgr->logList) {
            log = ilogMgr->internalLog;
            if(log->level > level || log->level == LogLevelNull || log->type == LogTypeNull) {
                continue;
            } else {
                ilogOutput(log, level, output, len);
            }
        } else {
            node = ilogMgr->logList;
            while(node) {
                log = node->log;
                node = node->next;
                if(log->level > level || log->level == LogLevelNull || log->type == LogTypeNull) {
                    continue;
                }
                ilogOutput(log, level, output, len);
            }
        }
    }
    return 0;
}

ILOG_API int ilogWriteLog(LogLevel level, const char *file, int line, const char *func, const char *format, ...)
{
    LogTime t;
    LogSource src;
    unsigned long pid, tid;
    va_list va;

    if(!ilogMgr) {
        ilogInit();
    }
    pid = _getpid();
    tid = _gettid();
    src.file = file;
    src.line = line;
    src.func = func;
    t = getCurrentTime();
    va_start(va, format);
    ilogMutexLock(&ilogMgr->mtxTxt);
    _vsnprintf(ilogMgr->txtBuf, ilogMgr->outBufSize, format, va);
    va_end(va);

    if(ilogMgr->socket >= 0) {
        ilogMutexLock(&ilogMgr->mtxClient);
        ilogSend(ilogMgr->socket, 0, level, t, src, pid, tid, ilogMgr->txtBuf);
        ilogMutexUnlock(&ilogMgr->mtxClient);
        ilogMutexUnlock(&ilogMgr->mtxTxt);
        return 0;
    }

    ilogWriteToHandle(level, t, src, pid, tid, ilogMgr->txtBuf);
    ilogMutexUnlock(&ilogMgr->mtxTxt);
    return 0;
}

ILOG_API int ilogWriteHex(LogLevel level, const char *file, int line, const char *func, void *buf, int len, const char *format, ...)
{
    LogTime t;
    LogSource src;
    unsigned long pid, tid;
    va_list va;

    if(!ilogMgr) {
        ilogInit();
    }
    pid = _getpid();
    tid = _gettid();
    src.file = file;
    src.line = line;
    src.func = func;
    t = getCurrentTime();
    va_start(va, format);
    ilogMutexLock(&ilogMgr->mtxTxt);
    _vsnprintf(ilogMgr->txtBuf, ilogMgr->outBufSize, format, va);
    va_end(va);

    if(ilogMgr->socket >= 0) {
        ilogMutexLock(&ilogMgr->mtxClient);
        ilogSend(ilogMgr->socket, len, level, t, src, pid, tid, ilogMgr->txtBuf);
        ilogMutexUnlock(&ilogMgr->mtxTxt);
        ilogSendHex(ilogMgr->socket, buf, len);
        ilogMutexUnlock(&ilogMgr->mtxClient);
        return 0;
    }

    ilogWriteToHandle(level, t, src, pid, tid, ilogMgr->txtBuf);
    ilogWriteHexToHandle(level, buf, len, 0);
    ilogMutexUnlock(&ilogMgr->mtxTxt);
    return 0;
}

ILOG_API const char *ilogLevelToString(LogLevel level)
{
    switch(level) {
    case LogLevelDebug:
        return "Debug";
    case LogLevelInfo:
        return "Info";
    case LogLevelNotice:
        return "Notice";
    case LogLevelWarning:
        return "Warning";
    case LogLevelError:
        return "Error";
    case LogLevelFatal:
        return "Fatal";
    default:
        return "Null";
    }
}

const unsigned char crc8Table[] = {
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83, 0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,
    0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E, 0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,
    0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0, 0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D, 0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
    0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5, 0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,
    0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58, 0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6, 0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,
    0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B, 0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
    0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F, 0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92, 0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,
    0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C, 0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,
    0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1, 0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49, 0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,
    0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4, 0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,
    0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A, 0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7, 0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35
};

typedef unsigned char byte;

static byte crc8Calc(const void *buf, size_t len)
{
    byte crc = 0;
    byte *p = (byte*)buf;
    while(len-- > 0) {
        crc = crc8Table[crc ^ *p];
        p++;
    }
    return crc;
}

typedef struct LogPackedData {
    short			header;
    int				line;
    size_t			txtSize;
    size_t			hexSize;
    size_t			packSize;		// 整个包大小，包含帧头，和文本数据
    LogLevel		level;
    LogTime			time;
    unsigned long	pid;
    unsigned long	tid;
    byte			crc8;
} LogPackedData;

static int ilogCheckPack(LogPackedData *data)
{
    byte crc8 = crc8Calc(data, (int)&((LogPackedData*)NULL)->crc8);
    return crc8 == data->crc8;
}

#ifdef _ilog_os_win32
static unsigned int __stdcall ilogServerCallback(void *arg)
#else
static void* ilogServerCallback(void *arg)
#endif
{
    int ret;
    int opt;
    int addrlen;
    int fdServer;
    char *txt;
    char buffer[8192];
    struct sockaddr_in clientAddr;

    fd_set fds;
    struct timeval tv;
    int socks[FD_SETSIZE];
    unsigned long pending;
    int count = 0;

    FD_ZERO(&fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    fdServer = *(int*)arg;
    free(arg);

    opt = 1;
    count = 1;
    memset(socks, 0xFF, sizeof(socks));
    socks[0] = fdServer;
    while(ilogMgr->isServerRunning) {
        int i;
        int client;
        LogSource src;
        LogPackedData data;

        FD_ZERO(&fds);
        for(i = 0; i < count; i++) {
            if(socks[i] != -1) {
                FD_SET((unsigned int)socks[i], &fds);
            }
        }
        ret = select(FD_SETSIZE, &fds, NULL, NULL, &tv);
        if(ret <= 0) {
            continue;
        }

        ilogMutexLock(&ilogMgr->mtxServer);
        if(FD_ISSET(fdServer, &fds)) {			// new connection or client request
            addrlen = sizeof(clientAddr);
            client = accept(fdServer, (struct sockaddr*)&clientAddr, &addrlen);
            if(client > 0) {
                ret = setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(int));
                for(i = 0; i < FD_SETSIZE; i++) {
                    if(socks[i] == -1) {
                        socks[i] = client;
                        count = max(count, i + 1);
                        break;
                    }
                }
            }
        } else {        // new connection or client request
            for(i = 1; i < count; i++) {	// serve to each client
                int sizeRead;
                client = socks[i];
                if(!FD_ISSET(client, &fds)) {
                    continue;
                }

            recvdata:
                memset(buffer, 0, sizeof(LogPackedData));
                sizeRead = recv(client, buffer, 2, 0);
                if(sizeRead < 0) {
                    for(i = 0; i < count; i++) {
                        if(socks[i] == client) {
                            socks[i] = -1;
                        }
                    }
                    closesocket(client);
                    continue;
                }
                if(*(short*)buffer == 0x474C) {
                    size_t offset = 0;
                    char temp[1024] = { 0 };		// 文件名+函数名
                    sizeRead = recv(client, buffer + 2, sizeof(LogPackedData) - 2, 0);
                    data = *(LogPackedData*)(buffer);
                    if(!ilogCheckPack(&data)) {
                        do {
                            ioctl(client, FIONREAD, &pending);
                            pending -= recv(client, buffer, min(pending, sizeof(buffer)), 0);
                        } while(pending > 0);
                        continue;
                    }
                    ret = data.packSize - sizeof(LogPackedData) - data.txtSize;
                    sizeRead = recv(client, temp, min(ret, sizeof(temp)), 0);
                    ret -= sizeRead;
                    while(ret > 0) {
                        ret -= recv(client, buffer, min(sizeof(buffer), ret), 0);
                    }
                    src.file = strtok_r(temp, "\n", &txt);
                    src.func = strtok_r(NULL, "\n", &txt);
                    src.line = data.line;
                    memset(buffer, 0, sizeof(buffer));
                    recv(client, buffer, data.txtSize, 0);
                    txt = buffer;
                    ilogWriteToHandle(data.level, data.time, src, data.pid, data.tid, txt);

                    offset = 0;
                    while(data.hexSize > 0) {
                        sizeRead = recv(client, buffer, min(1024, data.hexSize), 0);
                        ilogWriteHexToHandle(data.level, buffer, sizeRead, offset);
                        data.hexSize -= sizeRead;
                        offset += sizeRead;
                    }
                } else {
                    do {
                        ioctl(client, FIONREAD, &pending);
                        pending -= recv(client, buffer, min(pending, sizeof(buffer)), 0);
                    } while(pending > 0);
                    continue;
                }
                ioctl(client, FIONREAD, &pending);
                if(pending > 0) {
                    goto recvdata;
                }
            }	// serve to each client
        }	// new connection or client request

        ilogMutexUnlock(&ilogMgr->mtxServer);
    }
    closesocket(fdServer);

#ifdef _ilog_os_win32
    _endthreadex(0);
    return 0;
#else
    pthread_exit(NULL);
    return NULL;
#endif
}

ILOG_API int ilogCreateServer(unsigned short port)
{
    int ret;
    int *sock;
    int addrlen;
    struct sockaddr_in server;

#ifdef _ilog_os_win32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if(!ilogMgr) {
        ilogInit();
    }

    sock = (int*)malloc(sizeof(int));
    if(!sock) {
        return -1;
    }
    *sock = socket(AF_INET, SOCK_STREAM, 0);
    if(*sock < 0) {
        free(sock);
        return -1;
    }

    //long opt = 1;
    //ioctlsocket(*sock, FIONBIO, &opt);

    addrlen = sizeof(server);
    memset(&server, 0, addrlen);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(port);

    if(bind(*sock, (struct sockaddr*)&server, addrlen) < 0) {
        free(sock);
        return -2;
    }

    ret = listen(*sock, 21);
    (void)ret;

    ilogMgr->isServerRunning = 1;
#ifdef _ilog_os_win32
    ilogMgr->threadServer = (HANDLE)_beginthreadex(NULL, 0, ilogServerCallback, sock, 0, NULL);
#elif defined _ilog_os_unix
    pthread_create(&ilogMgr->threadServer, NULL, ilogServerCallback, sock);
#endif
    return 0;
}

static int ilogConnect(unsigned short port)
{
    int ret;
    int opt;
    int sock;
    int addrlen;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        return -1;
    }

    opt = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(int));

    addrlen = sizeof(server);
    memset(&server, 0, addrlen);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(port);

    ret = connect(sock, (struct sockaddr*)&server, addrlen);
    if(ret < 0) {
        return -2;
    }
    return sock;
}

static int ilogSend(int sock, int hexSize, LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *txt)
{
    int ret;
    int txtSize;
    char buf[1024];
    LogPackedData *data;

    txtSize = strlen(txt) + 1;
    if(txtSize > 8192) {	// 限制日志正文长度
        return 0;
    }
    ret = _snprintf(buf + sizeof(LogPackedData), sizeof(buf) - sizeof(LogPackedData), "%s\n%s\n", src.file, src.func);

    data = (LogPackedData*)buf;
    data->header = 0x474C;
    data->line = src.line;
    data->txtSize = txtSize;
    data->hexSize = hexSize;
    data->packSize = sizeof(LogPackedData) + ret + txtSize;
    data->level = level;
    data->time = time;
    data->pid = pid;
    data->tid = tid;
    data->crc8 = crc8Calc(data, (int)&((LogPackedData*)NULL)->crc8);
    ret = send(sock, buf, ret + sizeof(LogPackedData), 0);
    ret = send(sock, txt, strlen(txt) + 1, 0);
    return 0;
}

static int ilogSendHex(int sock, void *buf, int len)
{
    int offset = 0;
    do {
        int sizeSend;
        sizeSend = send(sock, (char*)buf + offset, min(len - offset, 1024), 0);
        offset += sizeSend;
    } while(offset < len);
    return 0;
}
