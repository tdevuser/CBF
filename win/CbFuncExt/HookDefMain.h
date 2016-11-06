
#ifndef _MAIN_HOOK_DEF_H_
#define _MAIN_HOOK_DEF_H_

#ifdef __cplusplus
extern "C"
{
#endif
    
    
// open();
extern int (*g_fpnext_open)(const char* pczFileName, int nFlags);
int next_open(const char* pczFileName, int nFlags);
int hook_open(const char* pczFileName, int nFlags);
    
// read();
extern int (*g_fpnext_read)(int fd, void* pBuf, size_t nLen );
int next_read(int fd, void* pBuf, size_t nLen );
int hook_read(int fd, void* pBuf, size_t nLen );
    
// write();
extern int (*g_fpnext_write)(int fd, const void* pBuf, size_t nCount);
int next_write(int fd, const void* pBuf, size_t nCount);
int hook_write(int fd, const void* pBuf, size_t nCount);
    
// close();
extern int (*g_fpnext_close)(int fd);
int next_close(int fd);
int hook_close(int fd);
  
    
 
    
    
#ifdef __cplusplus
}
#endif

#endif /* _MAIN_HOOK_DEF_H_ */
