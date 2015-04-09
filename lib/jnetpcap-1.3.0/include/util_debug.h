
// Include this file after jni.h is included. It undefines MS compiler, def for
// gcc specific one.
//
#ifndef Include_util_debug_h
#define Include_util_debug_h

#define JNIEXPORT extern "C"

#undef __declspec
#define __declspec(a) extern "C"

#include <stdarg.h>

#define DEBUG_MAX_LEVEL	10

#define DEBUG_TRACE 10
#define	DEBUG_INFO  8
#define DEBUG_WARN  6
#define DEBUG_ERROR 4

#define DEFAULT_LEVEL DEBUG_TRACE
#define DEFAULT_INDENT_CHAR '.'

extern int  debug_get_level();
extern void debug_set_level(int level);
extern void debug_inc();
extern void debug_dec();
extern void debug_reset();
extern void debug_vmsg(const char *type, const char *msg, const char *fmt, va_list ap);
extern void debug_msg(const char *type, const char *msg, const char *fmt, ...);
extern void debug_trace(const char *msg, const char *fmt, ...);
extern void debug_warn(const char *msg, const char *fmt, ...);
extern void debug_error(const char *msg, const char *fmt, ...);
extern void debug_info(const char *msg, const char *fmt, ...);
extern void debug_enter(const char *method);
extern void debug_exit(const char *method);

#define DEBUG_MAX_NAME			256
#define DEBUG_DEFAULT_LEVEL 	TRACE

/*** 
 ********  Temporarily backedout
class Debug {
public:
	enum Level {
		ALL,
		TRACE,
		INFO,
		WARN,
		ERR,
		NONE,
		UNDEFINED
	};
	
private:
	Level level;
	int indentation;
	char indentBuffer[DEBUG_MAX_LEVEL + 2];
	char indentChar;
	Debug	*parent;
	char name[DEBUG_MAX_NAME];
	
public:
	Debug(const char *name, Debug *parent);
	Debug(const char *name);
	Debug(const char *name, Level defaultLevel);
	~Debug() { }
	void setLevel(Level level);
	Level getLevel();
	void inc();
	void dec();
	void reset();
	
	void msg(Level type, char *msg, char *fmt, ...);
	void trace(char *msg, char *fmt, ...);
	void info(char *msg, char *fmt, ...);
	void warn(char *msg, char *fmt, ...);
	void error(char *msg, char *fmt, ...);
	
	void enter(char *method);
	void exit(char *method);

	
private:
	void vmsg(Level type, char *msg, char *fgm, va_list ap);
	char *indent();
	char *getLevelName(Level level);
	static char *levelNames[ERR + 1];
	static Debug global_logger;
	static Debug null_logger;
};

****************/

#endif
