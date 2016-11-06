
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "HookDefMain.h"
#include "CBFuncAPI.h"
#include "HookCode.h"

extern CHookCode   g_Hook;
extern PIProtectorAPI g_PIApi;


// mkdir
int	(*g_fpnext_mkdir)(const char *pathname, mode_t mode);
int	hook_mkdir(const char *pathname, mode_t mode)
{
    int nRet = 0;
    nRet = g_fpnext_mkdir( pathname, mode );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %d ), %d", pathname, mode, nRet );
    return nRet;
}

// rmdir
int	(*g_fpnext_rmdir)(const char *pathname);
int	hook_rmdir(const char *pathname)
{
    int nRet = 0;
    nRet = g_fpnext_rmdir( pathname );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s ), %d", pathname, nRet );
    return nRet;
}

// mknod
int	(*g_fpnext_mknod)(const char *pathname, mode_t mode, dev_t dev);
int	hook_mknod(const char *pathname, mode_t mode, dev_t dev)
{
    int nRet = 0;
    nRet = g_fpnext_mknod( pathname, mode, dev );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %d, %d ), %d", pathname, mode, dev, nRet );
    return nRet;
}

// remove
int	(*g_fpnext_remove)(const char* pathname);
int	hook_remove(const char* pathname)
{
    int nRet = 0;
    nRet = g_fpnext_remove( pathname );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s ), %d", pathname, nRet );
    return nRet;
}

// rename
int	(*g_fpnext_rename)(const char* oldpath, const char* newpath );
int	hook_rename(const char *oldpath, const char *newpath)
{
    int nRet = 0;
    nRet = g_fpnext_rename( oldpath, newpath );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %s ), %d", oldpath, oldpath, nRet );
    return nRet;
}





// create
int (*g_fpnext_creat)(const char *pathname, mode_t mode);
int hook_creat(const char *pathname, mode_t mode)
{
    int nRet = 0;
    nRet = g_fpnext_creat( pathname, mode );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %d ), %d", pathname, mode, nRet );
    return nRet;
}

// open();
int (*g_fpnext_open)(const char* pczFileName, int nFlags);
int next_open(const char* pczFileName, int nFlags)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
int hook_open(const char* pczFileName, int nFlags)
{
    int nRet = 0;
    nRet = g_fpnext_open( pczFileName, nFlags );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %d ), %d", pczFileName, nFlags, nRet );
    return nRet;
}

// read();
ssize_t (*g_fpnext_read)(int fd, void* pBuf, size_t nBytes );
ssize_t next_read(int fd, void* pBuf, size_t nBytes )
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
ssize_t hook_read(int fd, void* pBuf, size_t nBytes )
{
    ssize_t nRet = 0;
    nRet = g_fpnext_read( fd, pBuf, nBytes );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", fd, pBuf, nBytes, nRet );
    return nRet;
}

// write();
ssize_t (*g_fpnext_write)(int fd, const void* pBuf, size_t nCount);
ssize_t next_write(int fd, const void* pBuf, size_t nCount)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
ssize_t hook_write(int fd, const void* pBuf, size_t nCount)
{
    ssize_t nRet = 0;
    nRet = g_fpnext_write( fd, pBuf, nCount );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", fd, pBuf, nCount, nRet );
    return nRet;
}

// close();
int (*g_fpnext_close)(int fd);
int next_close(int fd)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return -1;
}
int hook_close(int fd)
{
    int nRet = 0;
    nRet = g_fpnext_close(fd);
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d ), %d", fd, nRet );
    return nRet;
}


int (*g_fpnext_stat)(const char *path, struct stat *buf);
int hook_stat(const char *path, struct stat *buf)
{
    int nRet = 0;
    nRet = g_fpnext_stat( path, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %p ), %d", path, buf, nRet );
    return nRet;
}


int (*g_fpnext_fstat)(int fd, struct stat *buf);
int hook_fstat(int fd, struct stat *buf)
{
    int nRet = 0;
    nRet = g_fpnext_fstat( fd, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p ), %d", fd, buf, nRet );
    return nRet;
}

int (*g_fpnext_lstat)(const char *path, struct stat *buf);
int hook_lstat(const char *path, struct stat *buf)
{
    int nRet = 0;
    nRet = g_fpnext_lstat( path, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %p ), %d", path, buf, nRet );
    return nRet;
}



int	(*g_fpnext_fstat64)(int fildes, struct stat64 *buf);
int	hook_fstat64(int fildes, struct stat64 *buf)
{
    int nRet = 0;
    nRet = g_fpnext_fstat64( fildes, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p ), %d", fildes, buf, nRet );
    return nRet;
}

int	(*g_fpnext_lstat64)(const char* path, struct stat64* buf);
int	hook_lstat64( const char* path, struct stat64* buf)
{
    int nRet = 0;
    nRet = g_fpnext_lstat64( path, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %p ), %d", path, buf, nRet );
    return nRet;
}

int	(*g_fpnext_stat64)(const char* path, struct stat64* buf);
int	hook_stat64(const char* path, struct stat64* buf)
{
    int nRet = 0;
    nRet = g_fpnext_stat64( path, buf );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %p ), %d", path, buf, nRet );
    return nRet;
}


int (*g_fpnext_truncate)(const char* pczPath, off_t nLength );
int hook_truncate(const char* pczPath, off_t nLength )
{
    int nRet = 0;
    nRet = g_fpnext_truncate( pczPath, nLength );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %ld ), %d", pczPath, nLength, nRet );
    return nRet;
}

int (*g_fpnext_ftruncate)(int fd, off_t nLength );
int hook_ftruncate(int fd, off_t nLength )
{
    int nRet = 0;
    nRet = g_fpnext_ftruncate( fd, nLength );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %ld ), %d", fd, nLength, nRet );
    return nRet;
}

int (*g_fpnext_link)(const char *oldpath, const char *newpath);
int hook_link(const char *oldpath, const char *newpath)
{
    int nRet = 0;
    nRet = g_fpnext_link( oldpath, newpath );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %s ), %d", oldpath, newpath, nRet );
    return nRet;
}

int (*g_fpnext_unlink)(const char* pczPath);
int	hook_unlink(const char* pczPath)
{
    int nRet = 0;
    nRet = g_fpnext_unlink( pczPath );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s ), %d", pczPath, nRet );
    return nRet;
}


int	(*g_fpnext_symlink)(const char *target, const char *linkpath);
int hook_symlink(const char *target, const char *linkpath)
{
    int nRet = 0;
    nRet = g_fpnext_symlink( target, linkpath );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %s ), %d", target, linkpath, nRet );
    return nRet;
}


int (*g_fpnext_mmap)(void* pAddr, size_t nLen, int nProt, int nFlags, int fd, off_t Offset);
int	hook_mmap(void* pAddr, size_t nLen, int nProt, int nFlags, int fd, off_t Offset)
{
    int nRet = 0;
    nRet = g_fpnext_mmap( pAddr, nLen, nProt, nFlags, fd, Offset );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %d, %d, %d, %d, %d ), %d", pAddr, nLen, nProt, nFlags, fd, Offset, nRet );
    return nRet;
}

         
int (*g_fpnext_munmap)(void* pAddr, size_t nLen);
int	hook_munmap(void* pAddr, size_t nLen)
{
    int nRet = 0;
    nRet = g_fpnext_munmap( pAddr, nLen );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %d ), %d", pAddr, nLen, nRet );
    return nRet;
}


// ioctl
int (*g_fpnext_ioctl)(int d, int request, ...);
int hook_ioctl(int d, int request, ... )
{
    int nRet = 0;

    va_list vlist;
    va_start( vlist, request );
    nRet = g_fpnext_ioctl( d, request, vlist );
    va_end(vlist);
    
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %d ), %d", d, request, nRet );
    return nRet;
}


int (*g_fpnext_fcntl)(int fd, int cmd, ... /* arg */ );
int hook_fcntl(int fd, int cmd, ... /* arg */ )
{
    int nRet = 0;
    va_list vlist;
    va_start( vlist, cmd );
    nRet = g_fpnext_fcntl( fd, cmd, vlist );
    va_end(vlist);
    
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %d ), %d", fd, cmd, nRet );
    return nRet;
}

// socket
int (*g_fpnext_socket)(int domain, int type, int protocol);
int hook_socket(int domain, int type, int protocol)
{
    int nRet = 0;
    nRet = g_fpnext_socket( domain, type, protocol );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %d, %d ), %d", domain, type, protocol, nRet );
    return nRet;
}

int (*g_fpnext_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int nRet = 0;
    nRet = g_fpnext_connect( sockfd, addr, addrlen );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", sockfd, addr, addrlen, nRet );
    return nRet;
    
}

ssize_t (*g_fpnext_send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t hook_send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t nRet = 0;
    nRet = g_fpnext_send( sockfd, buf, len, flags  );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d, %d ), %d", sockfd, buf, len, flags, nRet );
    return nRet;
}


ssize_t (*g_fpnext_sendto)( int sockfd,
                            const void *buf, size_t len, int flags,
                            const struct sockaddr *dest_addr, socklen_t addrlen );
ssize_t hook_sendto( int sockfd,
                     const void *buf, size_t len, int flags,
                     const struct sockaddr* dest_addr, socklen_t addrlen )
{
    ssize_t nRet = 0;
    nRet = g_fpnext_sendto( sockfd, buf, len, flags, dest_addr, addrlen );
//  g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d, %d, %p, %d ), %d", sockfd, buf, len, flags, dest_addr, addrlen, nRet );
    return nRet;
}


ssize_t (*g_fpnext_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
ssize_t hook_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    ssize_t nRet = 0;
    nRet = g_fpnext_sendmsg( sockfd, msg, flags );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", sockfd, msg, flags, nRet );
    return nRet;
}


ssize_t (*g_fpnext_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t nRet = 0;
    nRet = g_fpnext_recv( sockfd, buf, len, flags );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d, %d ), %d", sockfd, buf, len, flags, nRet );
    return nRet;
}


ssize_t (*g_fpnext_recvfrom)( int sockfd, void *buf, size_t len, int flags,
                              struct sockaddr *src_addr, socklen_t *addrlen );
ssize_t hook_recvfrom( int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen )
{
    ssize_t nRet = 0;
    nRet = g_fpnext_recvfrom( sockfd, buf, len, flags, src_addr, addrlen );
//  g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d, %d, %p, %p ), %d", sockfd, buf, len, flags, src_addr, addrlen , nRet );
    return nRet;
}


ssize_t (*g_fpnext_recvmsg)(int sockfd, struct msghdr *msg, int flags);
ssize_t hook_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t nRet = 0;
    nRet = g_fpnext_recvmsg( sockfd, msg, flags );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", sockfd, msg, flags, nRet );
    return nRet;
}






// fork();
pid_t (*g_fpnext_fork)();
pid_t hook_fork()
{
    pid_t pid = 0;
    pid = g_fpnext_fork();
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "(), %d", pid );
    return pid;
}

// execl();
pid_t (*g_fpnext_execl)( const char* pczPath, const char* pczArg, ... );
pid_t hook_execl( const char* pczPath, const char* pczArg, ... )
{
    pid_t pid = 0;
    va_list vlist;
    char czBuf[MAX_PATH];

    memset( czBuf, 0, sizeof(czBuf) );
    
    va_start( vlist, pczArg );
    pid = g_fpnext_execl( pczPath, pczArg, vlist );
    g_PIApi.GetBufferFormat( czBuf, sizeof(czBuf), pczArg, vlist );
    va_end( vlist );
    
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %s ), %d", pczPath, czBuf, pid );
    return pid;
}

// execv();
pid_t (*g_fpnext_execv)( const char* pczPath, char* const argv[] );
pid_t hook_execv( const char* pczPath, char* const argv[] )
{
    pid_t pid = 0;
    
    pid = g_fpnext_execv( pczPath, argv );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "(), %d", pid );
    return pid;
}

// exit();
void (*g_fpnext_exit)( int status );
void hook_exit( int status )
{
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d ), ", status );
    g_fpnext_exit( status );
}

//
// cups
//
cups_dest_t* (*g_fpnext_cupsGetDests)( const char *name, const char *instance, int num_dests, cups_dest_t *dests );
cups_dest_t* hook_cupsGetDests(const char *name, const char *instance, int num_dests, cups_dest_t *dests )
{
    cups_dest_t* pRet = NULL;
    pRet = g_fpnext_cupsGetDests( name, instance, num_dests, dests );
    
    // g_PIApi.HookAPI_LogWritePrint( __FUNCTION__, "( %s, %d, %p ), %p", name, num_dests, dests, pRet  );
    
    return pRet;
}

void (*g_fpnext_cupsFreeDests)( int num_jobs, cups_job_t *jobs );
void hook_cupsFreeDests( int num_jobs, cups_job_t *jobs )
{
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p ), ", num_jobs, jobs );
    g_fpnext_cupsFreeDests( num_jobs, jobs );
}

http_status_t
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
                  int last_document )
{
    http_status_t Ret;
    
    Ret = g_fpnext_cupsStartDocument( http, name, job_id, docname, format, last_document );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %s, %d, %s, %s, %d), %d",
                                  http, name, job_id, docname, format, last_document, Ret );
    return Ret;
}


ipp_status_t (*g_fpnext_cupsFinishDocument)(http_t *http, const char *name );
ipp_status_t hook_cupsFinishDocument(http_t *http, const char *name )
{
    ipp_status_t status;
    
    status = g_fpnext_cupsFinishDocument(http, name);
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %s ), %d", http, name, status );
    return status;
}


int (*g_fpnext_cupsPrintFile)(const char *name, const char *filename, const char *title, int num_options, cups_option_t *options);
int hook_cupsPrintFile(const char *name, const char *filename, const char *title, int num_options, cups_option_t *options)
{
    int nRet = 0;

    nRet = g_fpnext_cupsPrintFile( name, filename, title, num_options, options );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %s, %s, %d, %p ), %d", name, filename, title, num_options, options, nRet );
    return nRet;
}


int (*g_fpnext_cupsPrintFile2)(http_t *http,
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
                        cups_option_t *options )
{
    int nRet = 0;
    nRet = g_fpnext_cupsPrintFile2( http, name, filename, title, num_options, options );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %s, %s, %s, %d, %p ), %d", http, name, filename, title, num_options, options, nRet );
    return nRet;
}


int (*g_fpnext_cupsPrintFiles)(const char *name,
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
                        cups_option_t *options )
{
    int nRet = 0;
    nRet = g_fpnext_cupsPrintFiles(name, num_files, files, title, num_options, options );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s ), %d", name, nRet );
    return nRet;
}


int (*g_fpnext_cupsPrintFiles2)(http_t *http,
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
                                cups_option_t *options )
{
    int nRet = 0;
    nRet = g_fpnext_cupsPrintFiles2( http, name, num_files, files, title, num_options, options );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %p, %s, %p, %p, %d, %p )",
                                  http, name, num_files, files, title, num_options, options   );

    return nRet;
}
