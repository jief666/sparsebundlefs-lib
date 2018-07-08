
#define _FILE_OFFSET_BITS 64

#include "sys/types.h"
#include "stdint.h"



#ifdef __cplusplus
extern "C" {
#endif

int sparsebundlefs_getdatasize();
int sparsebundlefs_open(const char* path, const char*password, void* data);
size_t sparsebundlefs_getblocksize(void* sparsebundle_data);
size_t sparsebundlefs_getsize(void* sparsebundle_data);
char* sparsebundlefs_getpath(void* sparsebundle_data);
size_t sparsebundlefs_read(void* sparsebundle_data, uint8_t *buffer, size_t nbytes, off_t offset);
int sparsebundlefs_close(void* sparsebundle_data);

#ifdef __cplusplus
}
#endif

