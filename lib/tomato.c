
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>

#include <dirent.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/param.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>

#include <json/json.h>

#include "tomato.h"

//-------------------------------------------------------------------------------------------------------------------------------
void chld_reap(int sig)
{
	while(waitpid(-1, NULL, WNOHANG) > 0 ) {};
}

/*
 * Concatenates NULL-terminated list of arguments into a single
 * commmand and executes it
 * @param	argv	argument list
 * @param	path	NULL, ">output", or ">>output"
 * @param	timeout	seconds to wait before timing out or 0 for no timeout
 * @param	ppid	NULL to wait for child termination or pointer to pid
 * @return	return value of executed command or errno
 *
 * Ref: http://www.open-std.org/jtc1/sc22/WG15/docs/rr/9945-2/9945-2-28.html
 */
int _eval(char *const argv[], const char *path, int timeout, int *ppid)
{
	sigset_t set, sigmask;
	sighandler_t chld = SIG_IGN;
	pid_t pid, w;
	int status = 0;
	int fd;
	int flags;
	int sig;
	//int n;
	const char *p;
	char s[256];

	if (!ppid) {
		// block SIGCHLD
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, &sigmask);
		// without this we cannot rely on waitpid() to tell what happened to our children
		chld = signal(SIGCHLD, SIG_DFL);
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		status = errno;
		goto EXIT;
	}
	if (pid != 0) {
		// parent
		if (ppid) {
			*ppid = pid;
			return 0;
		}
		do {
			if ((w = waitpid(pid, &status, 0)) == -1) {
				status = errno;
				perror("waitpid");
				goto EXIT;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));

		if (WIFEXITED(status)) status = WEXITSTATUS(status);
EXIT:
		if (!ppid) {
			// restore signals
			sigprocmask(SIG_SETMASK, &sigmask, NULL);
			signal(SIGCHLD, chld);
			// reap zombies
			chld_reap(0);
		}
		return status;
	}
	
	// child

	// reset signal handlers
	for (sig = 0; sig < (_NSIG - 1); sig++)
		signal(sig, SIG_DFL);

	// unblock signals if called from signal handler
	sigemptyset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);

	setsid();

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

#if 0
		pid = getpid();

		cprintf("_eval +%ld pid=%d ", get_uptime(), pid);
		for (n = 0; argv[n]; ++n) cprintf("%s ", argv[n]);
		cprintf("\n");
		
		if ((fd = open("/dev/console", O_RDWR)) >= 0) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		else {
			sprintf(s, "/tmp/eval.%d", pid);
			if ((fd = open(s, O_CREAT|O_RDWR, 0600)) >= 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
			}
		}
		if (fd > STDERR_FILENO) close(fd);
#endif

	// Redirect stdout & stderr to <path>
	if (path) {
		flags = O_WRONLY | O_CREAT;
		if (*path == '>') {
			++path;
			if (*path == '>') {
				++path;
				// >>path, append
				flags |= O_APPEND;
			}
			else {
				// >path, overwrite
				flags |= O_TRUNC;
			}
		}
		
		if ((fd = open(path, flags, 0644)) < 0) {
			perror(path);
		}
		else {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}

	// execute command
	p = getenv("PATH");
	snprintf(s, sizeof(s), "%s%s/sbin:/bin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin", *p ? p : "", *p ? ":" : "");
	setenv("PATH", s, 1);

	alarm(timeout);
	execvp(argv[0], argv);
	
	perror(argv[0]);
	_exit(errno);
}

#define MAX_XSTART_ARGC 16
int _xstart(const char *cmd, ...)
{
	va_list ap;
	char *argv[MAX_XSTART_ARGC];
	int argc;
	int pid;

	argv[0] = (char *)cmd;
	argc = 1;
	va_start(ap, cmd);
	while ((argv[argc++] = va_arg(ap, char *)) != NULL) {
		if (argc >= MAX_XSTART_ARGC) {
//			printf("%s: too many parameters\n", __FUNCTION__);
			break;
		}
	}
	va_end(ap);

	return _eval(argv, NULL, 0, &pid);
}

int _xstart_pid(int *pid, const char *cmd, ...)
{
	va_list ap;
	char *argv[MAX_XSTART_ARGC];
	int argc;

	argv[0] = (char *)cmd;
	argc = 1;
	va_start(ap, cmd);
	while ((argv[argc++] = va_arg(ap, char *)) != NULL) {
		if (argc >= MAX_XSTART_ARGC) {
//			printf("%s: too many parameters\n", __FUNCTION__);
			break;
		}
	}
	va_end(ap);

	return _eval(argv, NULL, 0, pid);
}

//---------------------------------------------------------------------------------------------------------------
/*
文件相关函数
*/
int f_exists(const char *path)		// note: anything but a directory
{
	struct stat st;
	return (stat(path, &st) == 0) && (!S_ISDIR(st.st_mode));
}

unsigned long f_size(const char *path)		// 4GB-1	-1 = error
{
	struct stat st;
	if (stat(path, &st) == 0) return st.st_size;
	return (unsigned long)-1;
}

int f_read(const char *path, void *buffer, int max)
{
	int f;
	int n;

	if ((f = open(path, O_RDONLY)) < 0) return -1;
	n = read(f, buffer, max);
	close(f);
	return n;
}

int f_write(const char *path, const void *buffer, int len, unsigned flags, unsigned cmode)
{
	static const char nl = '\n';
	int f;
	int r = -1;
	mode_t m;

	m = umask(0);
	if (cmode == 0) cmode = 0666;
	if ((f = open(path, (flags & FW_APPEND) ? (O_WRONLY|O_CREAT|O_APPEND) : (O_WRONLY|O_CREAT|O_TRUNC), cmode)) >= 0) {
		if ((buffer == NULL) || ((r = write(f, buffer, len)) == len)) {
			if (flags & FW_NEWLINE) {
				if (write(f, &nl, 1) == 1) ++r;
			}
		}
		close(f);
	}
	umask(m);
	return r;
}

int f_read_string(const char *path, char *buffer, int max)
{
	if (max <= 0) return -1;
	int n = f_read(path, buffer, max - 1);
	buffer[(n > 0) ? n : 0] = 0;
	return n;
}

int f_write_string(const char *path, const char *buffer, unsigned flags, unsigned cmode)
{
	return f_write(path, buffer, strlen(buffer), flags, cmode);
}

static int _f_read_alloc(const char *path, char **buffer, int max, int z)
{
	unsigned long n;

	*buffer = NULL;
	if (max >= 0) {
		if ((n = f_size(path)) != (unsigned long)-1) {
			if (n < max) max = n;
			if ((!z) && (max == 0)) return 0;
			if ((*buffer = malloc(max + z)) != NULL) {
				if ((max = f_read(path, *buffer, max)) >= 0) {
					if (z) *(*buffer + max) = 0;
					return max;
				}
				free(buffer);
			}
		}
	}
	return -1;
}

int f_read_alloc(const char *path, char **buffer, int max)
{
	return _f_read_alloc(path, buffer, max, 0);
}

int f_read_alloc_string(const char *path, char **buffer, int max)
{
	return _f_read_alloc(path, buffer, max, 1);
}

int mkdir_if_none(const char *path)
{
	DIR *dp;

	dp = opendir(path);
	if(dp == NULL) {
		mkdir((char *)path, 0777);
		return 1;
	}

	closedir(dp);
	return 0;
}
//---------------------------------------------------------------------------------------------------------------------------
int uci_option_check(const uci_vt_t *v, const char *p)
{
	char *e;
	int n;
	long l;
	unsigned u[6];
	int ok;

	ok = 1;
	switch (v->vtype) {
	case VT_TEXT:
	case VT_LENGTH:
		n = strlen(p);
		if ((n < v->va.i) || (n > v->vb.i)) ok = 0;
		break;
	case VT_RANGE:
		l = strtol(p, &e, 10);
		if ((p == e) || (*e) || (l < v->va.l) || (l > v->vb.l)) ok = 0;
		break;
	case VT_IP:
		if ((sscanf(p, "%3u.%3u.%3u.%3u", &u[0], &u[1], &u[2], &u[3]) != 4) ||
			(u[0] > 255) || (u[1] > 255) || (u[2] > 255) || (u[3] > 255)) ok = 0;
		break;
	case VT_MAC:
		if ((sscanf(p, "%2x:%2x:%2x:%2x:%2x:%2x", &u[0], &u[1], &u[2], &u[3], &u[4], &u[5]) != 6) ||
			(u[0] > 255) || (u[1] > 255) || (u[2] > 255) || (u[3] > 255) || (u[4] > 255) || (u[5] > 255)) ok = 0;
		break;
#ifdef CONFIG_IPV6
	case VT_IPV6:
		if(strlen(p) > 0 || v->va.i) {
			if(inet_pton(AF_INET6, p, &addr) != 1) ok = 0;
		}
		break;
#endif
	default:
		break;
	}

	return ok;
}

int num_check_range(int num, int min, int max)
{
	if((num >= min)&&(num <= max)){
		return 1;
	} else {
		return 0;
	}
}

//--------------------------------------------------------------------------------------------------------------------------------------------------------
//JSON封装函数
static int print_tab(int i)
{
	for (; i>0; --i) {
		printf("\t");
	}

	return 0;
}

int json_tree_print(struct json_object *obj, const char *key, int level)
{
	json_type type = json_object_get_type(obj);
	int i = 0;

//for object
	if (type == json_type_object) {
		if (key) {
			print_tab(level);
			printf("%s:\n", key);
		}
		print_tab(level);
		printf("{\n");
		level++;

		json_object_object_foreach(obj, key, val) {
			struct json_object *tmp_obj = val;
			json_tree_print(tmp_obj, key, level);
		}

		level--;
		print_tab(level);
		printf("}\n");
	}

//for array
	else if ((type == json_type_array)) {
		if (key) {
			print_tab(level);
			printf("%s:\n", key);
		}

		print_tab(level);
		printf("[\n");
		level++;

		for(i=0; i < json_object_array_length(obj); i++) {
			struct json_object *array_obj = json_object_array_get_idx(obj, i);
			json_tree_print(array_obj, NULL, level);
		}

		level--;
		print_tab(level);
		printf("]\n");
	}

	else {
		print_tab(level);
		printf("%s:%s\n", key, json_object_to_json_string(obj));
	}

	return 0;
}

//----------------------------------------------------------------------------------------------------------------
/* become a daemon */
void daemonize(void)
{
	int maxfd;
	int i, pid;

/*
fork #1: exit parent process and continue in the background
*/
	if ((pid = fork()) < 0) {
		perror("couldn't fork");
		exit(2);
	} else if (pid > 0) {
		_exit(0);
	}

/*
fork #2: detach from terminal and fork again so we can never regain access to the terminal
*/
	setsid();
	if((pid = fork()) < 0) {
		perror("couldn't fork #2");
		exit(2);
	} else if(pid > 0) {
		_exit(0);
	}

/*
change to root directory and close file descriptors
*/
	umask(027);
	chdir("/");
	maxfd = getdtablesize();
	for(i = 0; i < maxfd; i++) {
		close(i);
	}

/*
use /dev/null for stdin, stdout and stderr
*/
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);
}

void kill_pid(int pid)
{
	int n;

	if (kill(pid, SIGTERM) == 0) {
		n = 30;
		while ((kill(pid, 0) == 0) && (n-- > 0)) {
			usleep(100 * 1000);
		}
		if (n < 0) {
			n = 20;
			while ((kill(pid, SIGKILL) == 0) && (n-- > 0)) {
				usleep(100 * 1000);
			}
		}
	}
}


/***************add*********************/
static int
url_download_header(const char *url, long long *length)
{
	int ret;
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);

		curl_easy_setopt(curl, CURLOPT_HEADER, 1L); 
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			__XDEBUG("errorn:%d curl_easy_perform(): %s\n", res, curl_easy_strerror(res));
			ret = -1;
		} else {
			long retcode = 0;
			long code = 0;
 	        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , &retcode); 
			if ( (code == CURLE_OK) && (retcode == 200) ){
				double size=0;
				curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD , &size); 
				*length=(long long)size;
				__XDEBUG("%lu bytes retrieved.\n", (long int)size);
			}
			else
				__XDEBUG("code=%lu. retcode=%lu\n", code,retcode);
			ret = 0;
		}
		curl_easy_cleanup(curl);
	} else {
		ret = -1;
	}

	return ret;
}	

static int find_pidof_name_other(const char *name)
{
	FILE *fd = NULL;
	char buff[16] = {0};
	char dir[1024] = {0};
	int len,pid;

	if(name == NULL) return -1;
	len = strlen(name);
	if(len >= sizeof(dir)-10) return -2;
	
	sprintf(dir,"pidof %s", (char *)name);
	
	fd = popen(dir, "r");
	if (!fd)
		return -1;

	if(0 == fread(buff, 1, 16, fd)) {
		pclose(fd);
		return 0;
	}
	pclose(fd);
	pid = atoi(buff);
	return pid;
}

static int find_pidof_name(const char *name)
{
	DIR	*dir  = NULL;
	struct dirent *d;
	int pid;
	int ret;
	int len;

	char *p;
	char buf[256] = {0};
	char path[PATH_MAX+1];
	return 10000;

	if(name == NULL) return -1;
	len = strlen(name);
	if(len >= sizeof(buf)) return -2;

	dir = opendir("/proc");
	if (!dir) {
		return -3;
	}

	while ((d = readdir(dir)) != NULL) {
		if ((pid = atoi(d->d_name)) == 0) continue;

//		printf("pid=%d d->name=%s\n", pid, d->d_name);
//		printf("d->d_name=%s\n", d->d_name);

		sprintf(path, "/proc/%s/comm", d->d_name);
		ret = f_read_string(path, buf, sizeof(buf));

//		printf("name=%s\n", buf);

		if(ret > 0) {
//			printf("name is %s,bug is %s\n,buf len-1 is %c,buf len is %d\n",name,buf,buf[len-1], (int)(buf[len]));
			if((memcmp(name, buf, strlen(name)) == 0)&&(buf[len] == '\n')) {
				closedir(dir);
				return pid;
			}
		}
		sprintf(path, "/proc/%s/exe", d->d_name);
		len = readlink(path, buf, sizeof(buf));
		if((len > 0)&&(len < sizeof(buf))) {
			buf[len] = 0;
			p = strstr(buf, name);
			if(p == NULL) continue;
			if((strlen(p) != strlen(name)))continue;
//printf("11name=%s p=%s pid=%d\n", name, p, pid);
			if(p == buf) {
				closedir(dir);
				return pid;
			}
			else {
//printf("22name=%s p=%s pid=%d\n", name, p, pid);
				--p;
				if(*p == '/') {
					closedir(dir);
					return pid;
				}
			}
		}
	}

	closedir(dir);				//don't forget closedir
	return  0;
}



