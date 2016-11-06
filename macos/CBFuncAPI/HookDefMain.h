
#ifndef _MAIN_HOOK_DEF_H_
#define _MAIN_HOOK_DEF_H_


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <cups/cups.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C"
{
#endif


// mkdir
extern int (*g_fpnext_mkdir)(const char *pathname, mode_t mode);
int	hook_mkdir(const char *pathname, mode_t mode);
    
// rmdir
extern int (*g_fpnext_rmdir)(const char *pathname);
int	hook_rmdir(const char *pathname);

// mknod
extern int (*g_fpnext_mknod)(const char *pathname, mode_t mode, dev_t dev);
int	hook_mknod(const char *pathname, mode_t mode, dev_t dev);

// remove
extern int	(*g_fpnext_remove)(const char* pathname);
int	hook_remove(const char* pathname);
    
// rename
extern int (*g_fpnext_rename)(const char* oldpath, const char* newpath );
int	hook_rename(const char *oldpath, const char *newpath);


    
// create
extern int (*g_fpnext_creat)(const char *pathname, mode_t mode);
int hook_creat(const char *pathname, mode_t mode);
    
// open();
extern int (*g_fpnext_open)(const char* pczFileName, int nFlags);
int next_open(const char* pczFileName, int nFlags);
int hook_open(const char* pczFileName, int nFlags);
    
// read();
extern ssize_t (*g_fpnext_read)(int fd, void* pBuf, size_t nLen );
ssize_t next_read(int fd, void* pBuf, size_t nLen );
ssize_t hook_read(int fd, void* pBuf, size_t nLen );
    
// write();
extern ssize_t (*g_fpnext_write)(int fd, const void* pBuf, size_t nCount);
ssize_t next_write(int fd, const void* pBuf, size_t nCount);
ssize_t hook_write(int fd, const void* pBuf, size_t nCount);
    
// close();
extern int (*g_fpnext_close)(int fd);
int next_close(int fd);
int hook_close(int fd);
    
    
    
extern int (*g_fpnext_stat)(const char *path, struct stat *buf);
int hook_stat(const char *path, struct stat *buf);
    
extern int (*g_fpnext_fstat)(int fd, struct stat *buf);
int hook_fstat(int fd, struct stat *buf);

extern int (*g_fpnext_lstat)(const char *path, struct stat *buf);
int hook_lstat(const char *path, struct stat *buf);
    

    
extern int (*g_fpnext_fstat64)(int fildes, struct stat64 *buf);
int	hook_fstat64(int fildes, struct stat64 *buf);
    
extern int (*g_fpnext_lstat64)(const char* path, struct stat64* buf);
int	hook_lstat64( const char* path, struct stat64* buf);
    
extern int (*g_fpnext_stat64)(const char* path, struct stat64* buf);
int	hook_stat64(const char* path, struct stat64* buf);

    
    
extern int (*g_fpnext_truncate)(const char* pczPath, off_t nLengh );
int hook_truncate(const char* pczPath, off_t nLengh );

extern int (*g_fpnext_ftruncate)(int fd, off_t nLengh );
int hook_ftruncate(int fd, off_t nLengh );

extern int (*g_fpnext_link)(const char *oldpath, const char *newpath);
int hook_link(const char *oldpath, const char *newpath);
    
extern int (*g_fpnext_unlink)(const char* pczPath);
int	hook_unlink(const char* pczPath);
    
extern int (*g_fpnext_symlink)(const char *target, const char *linkpath);
int hook_symlink(const char *target, const char *linkpath);

extern int (*g_fpnext_mmap)(void* pAddr, size_t nLen, int nProt, int nFlags, int fd, off_t Offset);
int	hook_mmap(void* pAddr, size_t nLen, int nProt, int nFlags, int fd, off_t Offset);

extern int (*g_fpnext_munmap)(void* pAddr, size_t nLen);
int	hook_munmap(void* pAddr, size_t nLen);
    
    

extern int (*g_fpnext_ioctl)(int d, int request, ...);
int hook_ioctl(int d, int request, ... );

extern int (*g_fpnext_fcntl)(int fd, int cmd, ... /* arg */ );
int hook_fcntl(int fd, int cmd, ... /* arg */ );
    
// socket
extern int (*g_fpnext_socket)(int domain, int type, int protocol);
int hook_socket(int domain, int type, int protocol);

extern int (*g_fpnext_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    
extern ssize_t (*g_fpnext_send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t hook_send(int sockfd, const void *buf, size_t len, int flags);
    
    
extern ssize_t (*g_fpnext_sendto)(int sockfd, const void *buf, size_t len, int flags,
                                  const struct sockaddr *dest_addr, socklen_t addrlen );
    
ssize_t hook_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen );
    
    
extern ssize_t (*g_fpnext_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
ssize_t hook_sendmsg(int sockfd, const struct msghdr *msg, int flags);
    
    
extern ssize_t (*g_fpnext_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags);
    
    
extern ssize_t (*g_fpnext_recvfrom)( int sockfd, void *buf, size_t len, int flags,
                                     struct sockaddr *src_addr, socklen_t *addrlen );
    
ssize_t hook_recvfrom( int sockfd, void *buf, size_t len, int flags,
                       struct sockaddr *src_addr, socklen_t *addrlen );
    
    
extern ssize_t (*g_fpnext_recvmsg)(int sockfd, struct msghdr *msg, int flags);
ssize_t hook_recvmsg(int sockfd, struct msghdr *msg, int flags);
    
    
    

// fork();
extern pid_t (*g_fpnext_fork)();
pid_t hook_fork();
    
// execl();
extern pid_t (*g_fpnext_execl)( const char* pczPath, const char* pczArg, ... );
pid_t hook_execl( const char* pczPath, const char* pczArg, ... );

// execv();
extern pid_t (*g_fpnext_execv)( const char* pczPath, char* const argv[] );
pid_t hook_execv( const char* pczPath, char* const argv[] );

// exit();
extern void (*g_fpnext_exit)( int status );
void hook_exit( int status );
    
    
    
    
// cups
extern cups_dest_t*
(*g_fpnext_cupsGetDests)( const char *name, const char *instance, int num_dests, cups_dest_t *dests );
    
cups_dest_t*
hook_cupsGetDests(const char *name, const char *instance, int num_dests, cups_dest_t *dests );
    
extern void (*g_fpnext_cupsFreeDests)( int num_jobs, cups_job_t *jobs );
void hook_cupsFreeDests( int num_jobs, cups_job_t *jobs );

extern http_status_t
(*g_fpnext_cupsStartDocument)(http_t *http,
                              const char *name,
                              int job_id,
                              const char *docname,
                              const char *format,
                              int last_document );

http_status_t
hook_cupsStartDocument(http_t *http,
                       const char *name,
                       int job_id,
                       const char *docname,
                       const char *format,
                       int last_document );

    
extern ipp_status_t (*g_fpnext_cupsFinishDocument)(http_t *http, const char *name );
ipp_status_t hook_cupsFinishDocument(http_t *http, const char *name );

    
extern int (*g_fpnext_cupsPrintFile)(const char *name,
                                     const char *filename,
                                     const char *title,
                                     int num_options,
                                     cups_option_t *options);
int hook_cupsPrintFile(const char *name,
                       const char *filename,
                       const char *title,
                       int num_options,
                       cups_option_t *options);
    

extern int (*g_fpnext_cupsPrintFile2)(http_t *http,
                                      const char *name,
                                      const char *filename,
                                      const char *title,
                                      int num_options,
                                      cups_option_t *options  );
    
int hook_cupsPrintFile2(http_t *http,
                        const char *name,
                        const char *filename,
                        const char *title,
                        int num_options,
                        cups_option_t *options );
    
    
extern int (*g_fpnext_cupsPrintFiles)(const char *name,
                                      int num_files,
                                      const char **files,
                                      const char *title,
                                      int num_options,
                                      cups_option_t *options );

int hook_cupsPrintFiles(const char *name,
                        int num_files,
                        const char **files,
                        const char *title,
                        int num_options,
                        cups_option_t *options );
 
    
    
extern int (*g_fpnext_cupsPrintFiles2)(http_t *http,
                                       const char *name,
                                       int num_files,
                                       const char **files,
                                       const char *title,
                                       int num_options,
                                       cups_option_t *options );
int hook_cupsPrintFiles2(http_t *http,
                         const char *name,
                         int num_files,
                         const char **files,
                         const char *title,
                         int num_options,
                         cups_option_t *options );
    
    
    
    
    
    
    
    
    
#ifdef __cplusplus
}
#endif

#endif /* _MAIN_HOOK_DEF_H_ */
