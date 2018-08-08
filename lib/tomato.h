/*
从tomato源码中偷取的一些小函数
*/

//-------------------------------------------------------------------------------------------------------------------------------
extern void chld_reap(int sig);

typedef void (*sighandler_t) (int);
/* 
 * Concatenates NULL-terminated list of arguments into a single
 * commmand and executes it
 * @param	argv	argument list
 * @param	path	NULL, ">output", or ">>output"
 * @param	timeout	seconds to wait before timing out or 0 for no timeout
 * @param	ppid	NULL to wait for child termination or pointer to pid
 * @return	return value of executed command or errno
 */
extern int _eval(char *const argv[], const char *path, int timeout, pid_t *ppid);

/* Simple version of _eval() (no timeout and wait for child termination) */
#if 1
#define eval(cmd, bank_args...) ({ \
	char *bank_argv[] = { cmd, ## bank_args, NULL }; \
	_eval(bank_argv, NULL, 0, NULL); \
})
#else
#define eval(cmd, bank_args...) ({ \
	char *bank_argv[] = { cmd, ## bank_args, NULL }; \
	_eval(bank_argv, ">/dev/console", 0, NULL); \
})
#endif

#define xstart(args...) _xstart(args, NULL)
extern int _xstart(const char *cmd,...);
extern int _xstart_pid(int *pid, const char *cmd, ...);
//---------------------------------------------------------------------------------------------------------------------------------
#define FW_CREATE 0
#define FW_APPEND 1
#define FW_NEWLINE 2

extern int f_exists(const char *path);
extern unsigned long f_size(const char *path);
extern int f_read(const char *path, void *buffer, int max);
extern int f_write(const char *path, const void *buffer, int len, unsigned flags, unsigned cmode);
extern int f_read_string(const char *path, char *buffer, int max);
extern int f_write_string(const char *path, const char *buffer, unsigned flags, unsigned cmode);
extern int f_read_alloc(const char *path, char **buffer, int max);
extern int f_read_alloc_string(const char *path, char **buffer, int max);
extern int mkdir_if_none(const char *path);
//----------------------------------------------------------------------------------------------------------------------------------
/*
封装了字符串变量校验的小函数，从tomato源码中偷取，可用于uci变量初步校验，具体的校验需要和变量实际情况做进一步检查
*/
typedef union {
	int i;
	long l;
	const char *s;
} uci_varg_t;

typedef struct {
	enum {
		VT_NONE,		// no checking
		VT_LENGTH,		// check length of string
		VT_TEXT,		// strip \r, check length of string
		VT_RANGE,		// expect an integer, check range
		VT_IP,			// expect an ip address
		VT_MAC,			// expect a mac address
#ifdef CONFIG_IPV6
		VT_IPV6,
#endif
	} vtype;
	uci_varg_t va;
	uci_varg_t vb;
} uci_vt_t;

#define	V_NONE				VT_NONE,	{ }, 			{ }
#define V_01				VT_RANGE,	{ .l = 0 },		{ .l = 1 }
#define V_PORT				VT_RANGE,	{ .l = 2 },		{ .l = 65535 }
#define V_ONOFF				VT_LENGTH,	{ .i = 2 },		{ .i = 3 }
#define V_WORD				VT_LENGTH,	{ .i = 1 },		{ .i = 16 }
#define V_LENGTH(min, max)	VT_LENGTH,	{ .i = min },	{ .i = max }
#define V_TEXT(min, max)	VT_TEXT,	{ .i = min },	{ .i = max }
#define V_RANGE(min, max)	VT_RANGE,	{ .l = min },	{ .l = max }
#define V_IP				VT_IP,		{ },			{ }
#define V_OCTET				VT_RANGE,	{ .l = 0 },		{ .l = 255 }
#define V_NUM				VT_RANGE,	{ .l = 0 },		{ .l = 0x7FFFFFFF }

extern int uci_option_check(const uci_vt_t *v, const char *p);
#define VT_CHECK(T, P)		uci_option_check(&((uci_vt_t){T}), P)

extern int num_check_range(int num, int min, int max);

//-----------------------------------------------------------------------------------------------------------------------------------------------------
extern int json_tree_print(struct json_object *obj, const char *key, int level);

//-----------------------------------------------------------------------------------------
extern void daemonize(void);
extern void kill_pid(int pid);

