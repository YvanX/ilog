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
#include <windows.h>
#include <direct.h>
#include <io.h>
#define _ilog_os_win32
#elif defined __unix || defined __linux__ || defined __APPLE__
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/time.h>
#define _ilog_os_unix
#endif

#if defined _ilog_os_unix
#define TLS         __thread
#define _strdup		strdup
#define _snprintf   snprintf
#define _vsnprintf  vsnprintf
#define _getpid     (unsigned long)getpid
#define _gettid     (unsigned long)pthread_self
#define _mkdir(name, mode)	mkdir(name, mode)
#define _chdir		chdir
#define _getcwd		getcwd
#define _access		access
#define ACCESS_EXIST	F_OK
#define HOMEPATH	"HOME"
#elif defined _ilog_os_win32
#define TLS         __declspec(thread)
#define _getpid     (unsigned long)GetCurrentProcessId
#define _gettid     (unsigned long)GetCurrentThreadId
#define _mkdir(name, mode)	mkdir(name)
#define ACCESS_EXIST	0
#define HOMEPATH	"USERPROFILE"
#ifndef __MINGW32__
typedef long mode_t;
#endif
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

typedef struct _tag_ilog {
	LogLevel    level;
	LogType     type;
	char		tag[32];
	uint8_t		overwrite;				// 是否覆盖原日志文件
	uint8_t		rotateTime;				// 0: 不转档  1: 每天转档  2:每小时转档
	uint32_t	rotateSize;				// 按大小转档
	uint8_t     internalLog;			// 是否允许输出内部信息	
	const char*	fileName;
	FILE*		logFile;
	void*		ctx;
	LogStyleFunc	styleFunc;
	LogOutputFunc	outputFunc;
	LogFormatList	*formatList;
#if defined _ilog_os_win32
	HANDLE		syslog;
#endif
} ilog;

typedef struct _tag_log_node {
    ilog *log;
    struct _tag_log_node *next;
} LogList;

typedef struct _tag_ilogs {
	LogList		*logList;
	ilog		*internalLog;			// 如果logList为空，则输出到此日志句柄
	char		*outBuf;
    char        *txtBuf;                // snprintf 输出到这里，避免反复的申请内存
	char		*hexBuf;
	uint32_t	outBufSize;
	uint32_t	hexBufSize;
#if defined _ilog_os_unix
	int			syslogFlag;
	pthread_mutex_t mutex;
#elif defined _ilog_os_win32
	HANDLE mutex;
#endif
} ilogManager;

static ilogManager *ilogMgr = NULL;

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
	if (!name || name[0] == '\0')
		return -1;
	pwd = _getcwd(NULL, 0);
	ptr = path = _strdup(name);
	normalizePath(path);
	if (path[0] == '/') {
		ret = _chdir("/");
		if (ret == -1) {
			perror("chdir");
		}
		ptr++;
	}
	else if (path[0] == '~') {
		char *home;
		home = getenv(HOMEPATH);
		ret = _chdir(home);
		if (ret == -1) {
			perror("chdir");
		}
		ptr += 2;
	}

	while (*ptr != '\0') {
		int i;
		for (i = 0; *ptr != '/' && *ptr != '\0'; ptr++) {
			buf[i++] = *ptr;
		}
		buf[i] = '\0';

		if (_access(buf, ACCESS_EXIST) == -1) {
			ret = _mkdir(buf, mode);
			if (ret == -1) {
				perror("mkdir");
				break;
			}
			_chdir(buf);
		}
		else {
			ret = _chdir(buf);
			if (ret == -1) {
				perror("chdir");
				break;
			}
		}
		if (*ptr == '\0') {
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
	
	if (name == NULL) {
		return NULL;
	}

	path = _strdup(name);
	normalizePath(path);
	tmp = strrchr(path, '/');
	if (tmp) {
		*tmp = '\0';
		mkdir_r(path, 0777);
	}
	free(path);

	path = (char*)malloc(MAX_PATH);
	if (name[0] == '~') {
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
	for (i = 0; i < 11; i++) {
		if (c == attr[i]) {
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
	if (!str) {
		return head;
	}
	len = strlen(str);
	if (len == 0 || len > 256) {
		return head;
	}

	fill = 0;
	spec = -1;
	status = StatusStart;
	bufferReset();
	for (i = 0; i < len; i++) {
		char c = str[i];
		if (status == StatusStart) {
			if (c == '%') {
				if (str[i + 1] == '%') {
					i++;
					buf[offset++] = c;
					continue;
				}
				fill = 0;
				status = StatusEscape;
				if (offset == 0)
					continue;
			}
			else {
				buf[offset++] = c;
				continue;
			}
		}
		else if (status == StatusEscape) {
			if (c == '-') {
				bufferReset();
				status = StatusAlign;
				buf[offset++] = c;
				continue;
			}
			else if (c == '0') {
				fill = 1;
				bufferReset();
				status = StatusNumber;
				continue;
			}
			else if (c > '0' && c <= '9') {
				bufferReset();
				status = StatusNumber;
				buf[offset++] = c;
				continue;
			}
			else {
				status = StatusStart;
				spec = checkSpecifier(c);
				if (spec >= FormatDate && spec <= FormatDatetimems) {
					if (timeflag == 0) {
						timeflag = 1;
					}
					else {
						printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
						bufferReset();
						continue;
					}
				}
				if (spec == -1) {
					printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
					bufferReset();
					continue;
				}
			}
		}
		else if (status == StatusAlign) {
			if (c == '0') {
				fill = 1;
				status = StatusNumber;
				continue;
			}
			else if (c > '0' && c <= '9') {
				status = StatusNumber;
				buf[offset++] = c;
				continue;
			}
			else {
				status = StatusStart;
				spec = checkSpecifier(c);
				if (spec >= FormatDate && spec <= FormatDatetimems) {
					if (timeflag == 0) {
						timeflag = 1;
					}
					else {
						printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
						bufferReset();
						continue;
					}
				}
				if (spec == -1) {
					printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
					bufferReset();
					continue;

				}
			}
		}
		else if (status == StatusNumber) {
			if (c >= '0' && c <= '9') {
				buf[offset++] = c;
				continue;
			}
			else {
				status = StatusStart;
				spec = checkSpecifier(c);
				if (spec >= FormatDate && spec <= FormatDatetimems) {
					if (timeflag == 0) {
						timeflag = 1;
					}
					else {
						printf("%d: datetime has already added. ignored '%%%s%c'\n", __LINE__, buf, c);
						bufferReset();
						continue;
					}
				}
				if (spec == -1) {
					printf("%d: invalid conversion specifier. ignored '%%%s%c'\n", __LINE__, buf, c);
					bufferReset();
					continue;
				}
			}
		}

		tmp = (LogFormatList*)malloc(sizeof(LogFormatList));
		if (spec == -1) {
			tmp->attr = (void*)_strdup(buf);
		}
		else {
			int width = atoi(buf);
			int sign = width >= 0 ? 1 : -1;
			if (spec == FormatDatetimems) {
				sign = 1;
				width = clamp(ABS(width), 0, 6);
			}
			else if (spec == FormatSource) {
				width = clamp(ABS(width), 0, MAX_PATH);
			}
			else if (spec == FormatLine || spec == FormatPid || spec == FormatTid) {
				if (fill) sign = 1;		// 如果使用0填充，则不能使用左对齐
				width = clamp(ABS(width), 0, 16);
			}
			else if (spec == FormatFunction) {
				width = clamp(ABS(width), 0, 64);
			}
			else {
				width = clamp(ABS(width), 0, 32);
			}
			tmp->attr = (void*)(long)spec;
			tmp->fill = fill;
			tmp->width = sign * width;
		}
		tmp->next = NULL;
		if (tail != NULL) {
			tail->next = tmp;
			tail = tmp;
		}
		else {
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
	while (fmt) {
		if ((long)fmt->attr > FormatTagEnd) {
			free(fmt->attr);
		}
		tmp = fmt;
		fmt = fmt->next;
		free(tmp);
	}
}

static int ilogOpenSyslog(ilog *log)
{
	if (!log || !log->fileName) {
		return ILOG_ERROR_PARAM;
	}
#if defined _ilog_os_unix
	ilogMgr->syslogFlag = 1;
	openlog(log->fileName, LOG_PID, LOG_USER);
#elif defined _ilog_os_win32
	if (!log->syslog) {
		log->syslog = RegisterEventSourceA(NULL, log->fileName);
	}
#endif
	return 0;
}

static int ilogWriteSyslog(ilog *log, LogLevel level, char *buf, int buflen)
{
#if defined _ilog_os_unix
	int	syslogLevel;
	switch (level) {
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
	if (!log || !log->syslog) {
		return ILOG_ERROR_PARAM;
	}
	if (level == LogLevelDebug || level == LogLevelInfo || level == LogLevelNotice)
		syslogLevel = EVENTLOG_INFORMATION_TYPE;
	else if (level == LogLevelWarning)
		syslogLevel = EVENTLOG_WARNING_TYPE;
	else if (level == LogLevelError || level == LogLevelFatal)
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
	if (ilogMgr && ilogMgr->syslogFlag == 1) {
		ilogMgr->syslogFlag = 0;
		closelog();
	}
#elif defined _ilog_os_win32
	if (log->syslog) {
		DeregisterEventSource(log->syslog);
        log->syslog = NULL;
	}
#endif
	return 0;
}


static void ilogRelease(ilog *log)
{
	if (!log) {
		return;
	}
	if (log->logFile) {
		fclose(log->logFile);
	}
	if (log->fileName) {
		free((void*)log->fileName);
	}
	if (log->formatList) {
		releaseFormat(log->formatList);
	}
	ilogCloseSyslog(log);

	free(log);
}

int ilogInit()
{
	ilog *internalLog;
	if (ilogMgr) {
		return 0;
	}

	ilogMgr = (ilogManager*)malloc(sizeof(ilogManager));
	if (!ilogMgr) {
		return ILOG_ERROR_MEMORY;
	}
	ilogMgr->logList = NULL;
	ilogMgr->outBufSize = 2 * 1024;			// 2K
	ilogMgr->hexBufSize = 16 * 1024;		// 16K
	ilogMgr->outBuf = (char*)malloc(ilogMgr->outBufSize);
	ilogMgr->txtBuf = (char*)malloc(ilogMgr->outBufSize);
	ilogMgr->hexBuf = (char*)malloc(ilogMgr->hexBufSize);
	if (!ilogMgr->outBuf || !ilogMgr->txtBuf || !ilogMgr->hexBuf) {
		return ILOG_ERROR_MEMORY;
	}

	internalLog = ilogCreate(LogLevelDebug, LogTypeStdout);
	if (!internalLog) {
		return ILOG_ERROR_INTERNAL;
	}
	ilogSetStyle(internalLog, LogStyleFormat, ILOG_INTERNAL_FORMAT);
	ilogMgr->internalLog = internalLog;

#if defined _ilog_os_unix
	ilogMgr->syslogFlag = 0;
	pthread_mutex_init(&ilogMgr->mutex, NULL);
#elif defined _ilog_os_win32
	ilogMgr->mutex = CreateMutex(NULL, FALSE, NULL);
#endif
	return 0;
}

int ilogCleanup()
{
	if (!ilogMgr) {
		return 0;
	}

	while (ilogMgr->logList) {
		LogList *node = ilogMgr->logList;
		ilogMgr->logList = node->next;
		ilogRelease(node->log);
		free(node);
	}
	ilogRelease(ilogMgr->internalLog);
	free(ilogMgr->outBuf);
    free(ilogMgr->txtBuf);
	free(ilogMgr->hexBuf);

#if defined _ilog_os_unix
	pthread_mutex_destroy(&ilogMgr->mutex);
#elif defined _ilog_os_win32
	CloseHandle(ilogMgr->mutex);
#endif

	free(ilogMgr);
	return 0;
}

int ilogAddLog(ilog *log)
{
	LogList *node, *tail;
	if (!log) {
		return ILOG_ERROR_PARAM;
	}
	if (!ilogMgr) {
		ilogInit();
	}
	if (!ilogMgr) {
		return ILOG_ERROR_INTERNAL;
	}

	tail = ilogMgr->logList;
	while (tail) {
		if (tail->log == log) {
			return ILOG_ERROR_PARAM;
		}
		if (tail->next) {
			tail = tail->next;
		} else {
			break;
		}
	}

	node = (LogList*)malloc(sizeof(LogList));
	if (!node) {
		return ILOG_ERROR_MEMORY;
	}
	node->log = log;
	node->next = NULL;
	if (tail) {
		tail->next = node;
	} else {
		ilogMgr->logList = node;
	}

	if (!log->styleFunc && !log->formatList) {
		ilogSetStyle(log, LogStyleFormat, ILOG_INTERNAL_FORMAT);
	}

	if (log->type == LogTypeFile && log->fileName) {
		if (log->overwrite == 0) {
			log->logFile = createFile(log->fileName, "at");
		} else {
			log->logFile = createFile(log->fileName, "wt");
		}
	} else if (log->type == LogTypeSyslog && log->fileName) {
		ilogOpenSyslog(log);
	}
	return 0;
}

ilog* ilogCreate(LogLevel level, LogType type, ...)
{
	ilog *log;
	log = (ilog*)malloc(sizeof(ilog));
	if (!log) {
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
	log->ctx = NULL;
	log->formatList = NULL;
	log->styleFunc = NULL;
	log->outputFunc = NULL;

	if (type == LogTypeFile) {
		va_list va;
		va_start(va, type);
		log->fileName = _strdup(va_arg(va, char*));
		va_end(va);
	} else if (type == LogTypeSyslog) {
		va_list va;
		va_start(va, type);
		log->fileName = _strdup(va_arg(va, char*));
		va_end(va);
	} else if (type == LogTypeCallback) {
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

void ilogDestroy(ilog *log)
{
	LogList *node;
	if (!log  || !ilogMgr) {
		return;
	}

	node = ilogMgr->logList;
	// 删除头节点
	if (log == node->log) {
		ilogMgr->logList = node->next;
		ilogRelease(log);
		free(node);
		return;
	}

	while (node) {
		if (node->next && node->next->log == log) {
			LogList *tmp = node->next;
			node->next = tmp->next;
			ilogRelease(log);
			free(tmp);
			return;
		}
		node = node->next;
	}
}

int ilogSetLevel(ilog *log, LogLevel level)
{
	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}
	log->level = level;
	return 0;
}

int ilogSetOutputType(ilog *log, LogType type, ...)
{
	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}

	log->type = type;
	if (type == LogTypeFile) {
		va_list va;
		if (log->fileName) {
			free((void*)log->fileName);
		}
		va_start(va, type);
		log->fileName = _strdup(va_arg(va, char*));
		va_end(va);
		if (log == ilogMgr->internalLog) {
			if (log->logFile) {
				fclose(log->logFile);
			}
			if (log->overwrite == 0) {
				log->logFile = createFile(log->fileName, "at");
			} else {
				log->logFile = createFile(log->fileName, "wt");
			}
		}
	} else if (type == LogTypeSyslog) {
		va_list va;
		if (log->fileName) {
			free((void*)log->fileName);
		}
		va_start(va, type);
		log->fileName = _strdup(va_arg(va, char*));
		va_end(va);
		if (log == ilogMgr->internalLog) {
			ilogOpenSyslog(log);
		}
	} else if (type == LogTypeCallback) {
		va_list va;
		va_start(va, type);
		log->outputFunc = va_arg(va, LogOutputFunc);
		log->ctx = va_arg(va, void*);
		va_end(va);
	}
	return 0;
}

int ilogSetOpt(ilog *log, LogOpt opt, ...)
{
	va_list va;
	uint32_t value;

	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}

	va_start(va, opt);
	value = va_arg(va, uint32_t);
	va_end(va);
	switch (opt) {
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
		if (value != 0) {
			log->rotateTime = 2;
		} else if (log->rotateTime == 2) {
			log->rotateTime = 0;
		}
		break;
	case LogOptRotateByDay:
		if (value != 0) {
			log->rotateTime = 1;
		} else if (log->rotateTime == 1) {
			log->rotateTime = 0;
		}
		break;
	default:
		break;
	}
	return 0;
}

int ilogSetTag(ilog *log, const char *tag)
{
	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}
	if (!tag) {
		return ILOG_ERROR_PARAM;
	}
	_snprintf(log->tag, sizeof(log->tag), "%s", tag);
	return 0;
}

int ilogSetStyle(ilog *log, LogStyle style, ...)
{
	va_list va;
	va_start(va, style);
	if (style == LogStyleFormat) {
		char *format = va_arg(va, char*);
		va_end(va);
		return ilogSetStyleFormat(log, format);
	} else if (style == LogStyleCallback) {
		LogStyleFunc func = va_arg(va, LogStyleFunc);
		void *ctx = va_arg(va, void*);
		va_end(va);
		return ilogSetStyleCallback(log, func, ctx);
	} else {
		return ILOG_ERROR_PARAM;
	}
}

int ilogSetStyleFormat(ilog *log, const char *format)
{
	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}
	if (log->formatList) {
		releaseFormat(log->formatList);
	}
	log->formatList = parseFormat(format);
	if (!log->formatList) {
		return ILOG_ERROR_PARAM;
	}
	return 0;
}

int ilogSetStyleCallback(ilog *log, LogStyleFunc func, void *ctx)
{
	if (!ilogMgr) {
		ilogInit();
	}
	if (!log) {
		log = ilogMgr->internalLog;
	}
	log->styleFunc = func;
	log->ctx = ctx;
	return 0;
}

static void ilogMutexLock()
{
#if defined _ilog_os_unix
	pthread_mutex_lock(&ilogMgr->mutex);
#elif defined _ilog_os_win32
	WaitForSingleObject(ilogMgr->mutex, INFINITE);
#endif
}

static void ilogMutexUnlock()
{
#if defined _ilog_os_unix
	pthread_mutex_unlock(&ilogMgr->mutex);
#elif defined _ilog_os_win32
	ReleaseMutex(ilogMgr->mutex);
#endif
}

static int textAlign(char *buf, const char *str, int width, char fill)
{
	int len = strlen(str);
	int align = width < 0 ? 0 : 1;
	width = ABS(width);
	if (len >= width) {
		strcpy(buf, str);
		return len;
	}
	else {
		if (align == 0) {
			strcpy(buf, str);
			memset(buf + len, fill, width - len);
			buf[width] = '\0';
		}
		else if (align == 1) {
			memset(buf, fill, width - len);
			strcpy(buf + width - len, str);
		}
		return width;
	}
}

static const char *getBaseName(const char *name)
{
	int i;
	for (i = strlen(name); i >= 0; i--) {
		if (name[i] == '/' || name[i] == '\\') {
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

	if (!log || !log->formatList) {
		return 0;
	}
	fmt = log->formatList;
    
	while (fmt && buflen > 0) {
		if ((long)fmt->attr < FormatTagEnd) {
			FormatAttr spec = (FormatAttr)(long)fmt->attr;
			switch (spec) {
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
				if (fmt->width == 0 || fmt->width >= 6) {
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
				if (fmt->width == 0) {
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
				if (fmt->width == 0) {
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
				if (fmt->width != 0) {
					textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				} else {
					len = _snprintf(buf, buflen, "%s", number);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			case FormatFunction:
				if (fmt->width == 0) {
					len = _snprintf(buf, buflen, "%s", src.func);
					MoveBufPtr(buf, len, buflen);
				}
				else {
					textAlign(tmp, src.func, fmt->width, ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			case FormatPid:
				_snprintf(number, 16, "%ld", pid);
				if (fmt->width != 0) {
					textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				}
				else {
					len = _snprintf(buf, buflen, "%s", number);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			case FormatTid:
				_snprintf(number, 16, "%ld", tid);
				if (fmt->width != 0) {
					textAlign(tmp, number, fmt->width, fmt->fill ? '0' : ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				}
				else {
					len = _snprintf(buf, buflen, "%s", number);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			case FormatTag:
				if (!tag) {
					tag = "<no tag>";
				}
				if (fmt->width == 0) {
					len = _snprintf(buf, buflen, "%s", tag);
					MoveBufPtr(buf, len, buflen);
				}
				else {
					textAlign(tmp, tag, fmt->width, ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			case FormatText:
				if (fmt->width == 0) {
					len = _snprintf(buf, buflen, "%s", txt);
					MoveBufPtr(buf, len, buflen);
				}
				else {
					textAlign(tmp, txt, fmt->width, ' ');
					len = _snprintf(buf, buflen, "%s", tmp);
					MoveBufPtr(buf, len, buflen);
				}
				break;
			default:
				break;
			}
		}
		else {
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

static int ilogOutput(ilog *log, LogLevel level, char *buf, int len)
{
	int ret;
	if (len == 0 || !log || !buf) {
		return 0;
	}
    if(log->level == LogLevelNull) {
        return 0;
    }
	switch (log->type) {
	case LogTypeStdout:
		fwrite(buf, len, 1, stdout);
		break;
	case LogTypeStderr:
		fwrite(buf, len, 1, stderr);
		break;
	case LogTypeFile:
		if (log->logFile) {
			fwrite(buf, len, 1, log->logFile);
            fflush(log->logFile);
		}
		break;
	case LogTypeSyslog:
		ilogWriteSyslog(log, level, buf, len);
		break;
	case LogTypeCallback:
		if (log->outputFunc) {
			ret = log->outputFunc(log->ctx, level, buf, len);
			if (ret != len) {
				// 
			}
		}
	default:
		break;
	}
	return 0;
}

static void ilogWriteHexBase(ilog *log, LogLevel level, void *buf, int len)
{
	int i;
	int ret;
	int bytesLeft;
	int offset;
	char *ptr;
	int buflen;

	if (log->level > level || log->level == LogLevelNull || log->type == LogTypeNull) {
		return;
	}
	offset = 0;
	ptr = ilogMgr->hexBuf;
	buflen = ilogMgr->hexBufSize;

	while (offset < len) {
		int end;
		bytesLeft = min(len - offset, 16);
		end = offset + bytesLeft;
		ret = _snprintf(ptr, buflen, "0x%08x   ", offset);
		MoveBufPtr(ptr, ret, buflen);
		for (i = offset; i < end; i++) {
			ret = _snprintf(ptr, buflen, " %02X", ((unsigned char*)buf)[i]);
			MoveBufPtr(ptr, ret, buflen);
		}
		for (i = 16 - bytesLeft; i > 0; i--) {
			ret = _snprintf(ptr, buflen, "   ");
			MoveBufPtr(ptr, ret, buflen);
		}
		ret = _snprintf(ptr, buflen, "  ");
		MoveBufPtr(ptr, ret, buflen);
		for (i = offset; i < end; i++) {
			unsigned char c = ((unsigned char*)buf)[i];
			if (isprint(c) || c >= 0x80) {
				*ptr++ = c;
				buflen--;
			}
			else {
				*ptr++ = '.';
				buflen--;
			}
		}
		*ptr++ = '\n';
		buflen--;
		if (buflen <= 80) {
			*ptr = '\0';
			ilogOutput(log, level, ilogMgr->hexBuf, ptr - ilogMgr->hexBuf);
			ptr = ilogMgr->hexBuf;
			buflen = ilogMgr->hexBufSize;
		}
		offset += 16;
	}
	if (ptr != ilogMgr->hexBuf) {
		*ptr = '\0';
		ilogOutput(log, level, ilogMgr->hexBuf, ptr - ilogMgr->hexBuf);
	}
}

static int ilogWriteLogBase(ilog *log, LogLevel level, LogTime time, LogSource src, unsigned long pid, unsigned long tid, const char *txt)
{
	int len;
	if (!log) {
		return ILOG_ERROR_PARAM;
	}
	if (log->level > level || log->level == LogLevelNull || log->type == LogTypeNull) {
		return 0;
	}
	if (!log->styleFunc) {
		len = ilogFormamt(log, ilogMgr->outBuf, ilogMgr->outBufSize, level, time, src, pid, tid, log->tag, txt);
	} else {
		len = log->styleFunc(log->ctx, ilogMgr->outBuf, ilogMgr->outBufSize, level, time, src, pid, tid, log->tag, txt);
	}
	ilogOutput(log, level, ilogMgr->outBuf, len);
	return 0;
}

int ilogWriteLog(LogLevel level, const char *file, int line, const char *func, const char *format, ...)
{
	ilog *log;
	LogTime t;
	LogSource src;
	LogList *node;
	unsigned long pid, tid;
	va_list va;

	if (!ilogMgr) {
		ilogInit();
	}
	pid = _getpid();
	tid = _gettid();
	src.file = file;
	src.line = line;
	src.func = func;
	t = getCurrentTime();
	va_start(va, format);
	_vsnprintf(ilogMgr->txtBuf, ilogMgr->outBufSize, format, va);
	va_end(va);

	if (!ilogMgr->logList) {
		log = ilogMgr->internalLog;
		ilogMutexLock();
		ilogWriteLogBase(log, level, t, src, pid, tid, ilogMgr->txtBuf);
		ilogMutexUnlock();
		return 0;
	}

	node = ilogMgr->logList;
	ilogMutexLock();
	while (node) {
		ilogWriteLogBase(node->log, level, t, src, pid, tid, ilogMgr->txtBuf);
		node = node->next;
	}
	ilogMutexUnlock();
	return 0;
}

int ilogWriteHex(LogLevel level, const char *file, int line, const char *func, void *buf, int len, const char *format, ...)
{
	ilog *log;
	LogTime t;
	LogSource src;
	LogList *node;
	unsigned long pid, tid;
	va_list va;

	if (!ilogMgr) {
		ilogInit();
	}
	pid = _getpid();
	tid = _gettid();
	src.file = file;
	src.line = line;
	src.func = func;
	t = getCurrentTime();
	va_start(va, format);
	_vsnprintf(ilogMgr->txtBuf, ilogMgr->outBufSize, format, va);
	va_end(va);

	if (!ilogMgr->logList) {
		log = ilogMgr->internalLog;
		ilogMutexLock();
		ilogWriteLogBase(log, level, t, src, pid, tid, ilogMgr->txtBuf);
		ilogWriteHexBase(log, level, buf, len);
		ilogMutexUnlock();
		return 0;
	}

	node = ilogMgr->logList;
	ilogMutexLock();
	while (node) {
		ilogWriteLogBase(node->log, level, t, src, pid, tid, ilogMgr->txtBuf);
		ilogWriteHexBase(node->log, level, buf, len);
		node = node->next;
	}
	ilogMutexUnlock();
	return 0;
}

const char *ilogLevelToString(LogLevel level)
{
    switch (level) {
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
