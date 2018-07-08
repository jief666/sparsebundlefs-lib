#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pwd.h>
#include <stddef.h>

#include <fuse.h>

#include "../sparsebundlefs/sparsebundlefs.h"
//#include "../sparsebundleutil.h"

static const char image_path[] = "/sparsebundle.dmg";
void* sparsebundlefr_data_ptr;
char* mountpoint = 0;

static int sparsebundle_show_usage(char *program_name)
{
    fprintf(stderr, "usage: %s [-o options] [-s] [-f] [-D] [-h] <sparsebundle> <mountpoint>\n", program_name);
    fprintf(stderr, "       -s single thread\n");
    fprintf(stderr, "       -f foreground\n");
    fprintf(stderr, "       -D debug\n");
    fprintf(stderr, "       -h header only\n");
    fprintf(stderr, "       -P password (never use that for real password, only tests !!\n");
    return 1;
}

enum { SPARSEBUNDLE_OPT_DEBUG, SPARSEBUNDLE_OPT_HEADERONLY };
struct options_st {
	int headeronly;
	char* password;
	char* path;
};

static int sparsebundle_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    switch (key) {
    case SPARSEBUNDLE_OPT_DEBUG:
        setlogmask(LOG_UPTO(LOG_DEBUG));
        return 0;
    case SPARSEBUNDLE_OPT_HEADERONLY:
    	((struct options_st*)data)->headeronly = 1;
        return 0;
    case FUSE_OPT_KEY_NONOPT:
        if ( ((struct options_st*)data)->path ) {
        	if ( !mountpoint ) {
        		mountpoint = strdup(arg);
        	}
            return 1;
        }

        ((struct options_st*)data)->path = strdup(arg);
        return 0;
    }

    return 1;
}

static int sparsebundle_fuse_getattr(const char *path, struct stat *stbuf)
{
//syslog(LOG_DEBUG, "sparsebundle_getattr");
    memset(stbuf, 0, sizeof(struct stat));

    struct stat bundle_stat;
    stat(sparsebundlefs_getpath(sparsebundlefr_data_ptr), &bundle_stat);

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 3;
        stbuf->st_size = sizeof(sparsebundlefr_data_ptr);
    } else if (strcmp(path, image_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = sparsebundlefs_getsize(sparsebundlefr_data_ptr);
    } else
        return -ENOENT;

    stbuf->st_atime = bundle_stat.st_atime;
    stbuf->st_mtime = bundle_stat.st_mtime;
    stbuf->st_ctime = bundle_stat.st_ctime;

    return 0;
}

//using namespace std;

uint64_t times_opened = 0;

static int sparsebundle_fuse_open(const char *path, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_open(%s)", image_path);
    if (strcmp(path, image_path) != 0) {
    	syslog(LOG_DEBUG, "sparsebundle_open  return ENOENT");
        return -ENOENT;
    }
    if ((fi->flags & O_ACCMODE) != O_RDONLY) {
    	syslog(LOG_DEBUG, "sparsebundle_open flags=%x return EACCES", fi->flags);
        return -EACCES;
	}
    times_opened++;
syslog(LOG_DEBUG, "opened, now referenced %" PRId64" times", times_opened);

    return 0;
}

int sparsebundle_fuse_read(const char *path, char *buffer, size_t length, off_t offset, struct fuse_file_info *fi)
{
//syslog(LOG_DEBUG, "sparsebundle_fuse_read(%s, length=%zd, offset=%lld)", image_path,length, offset);
	size_t rv = sparsebundlefs_read(sparsebundlefr_data_ptr, (uint8_t*)buffer, length, offset);
//syslog(LOG_DEBUG, "sparsebundle_fuse_read(%s, length=%zd, offset=%lld) returns %zd", image_path,length, offset, rv);
	return (int)rv;
}

int sparsebundle_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
//syslog(LOG_DEBUG, "sparsebundle_readdir");

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    struct stat image_stat;
    sparsebundle_fuse_getattr(image_path, &image_stat);

    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);
    filler(buf, image_path + 1, &image_stat, 0);

    return 0;
}

int sparsebundle_fuse_release(const char *path, struct fuse_file_info *fi)
{
//syslog(LOG_DEBUG, "sparsebundle_release");

	times_opened--;

    return 0;
}

#ifdef DEBUG
static void print_hex(void *data, uint32_t len, const char* format, ...)
{
	uint32_t ctr;

	if (len > 512) {
		len = 512;
	}

	char buf[len*2+1];
	bzero(buf, sizeof(buf));
	for(ctr = 0; ctr < len; ctr++) {
		sprintf(buf + (ctr*2), "%02x", ((uint8_t *)data)[ctr]);
	}
	{
		char message[2000];
		va_list args;
		va_start(args, format);
		vsnprintf(message, sizeof(message), format, args);
		va_end(args);
		syslog(LOG_DEBUG, "%s : %s", message, buf);
	}
}
#endif

int main(int argc, char **argv)
{
    openlog("sparsebundlefs", LOG_CONS | LOG_PERROR, LOG_USER);
    setlogmask(~(LOG_MASK(LOG_DEBUG)));

    struct options_st options = {};

    struct fuse_opt sparsebundle_options[] = {
        FUSE_OPT_KEY("-D", SPARSEBUNDLE_OPT_DEBUG),
		FUSE_OPT_KEY("-h", SPARSEBUNDLE_OPT_HEADERONLY),
		{ "--pass=%s", offsetof(struct options_st, password), 1 },
        { 0, 0, 0 } // End of options
    };

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&args, &options, sparsebundle_options, sparsebundle_opt_proc);
    fuse_opt_add_arg(&args, "-oro"); // Force read-only mount


    if (!options.path)
        return sparsebundle_show_usage(argv[0]);

    sparsebundlefr_data_ptr = malloc(sparsebundlefs_getdatasize());
    int rv = sparsebundlefs_open(options.path, options.password, sparsebundlefr_data_ptr);
	if ( rv != 0 ) {
        fprintf(stderr, "Could not open sparse bundle '%s': %s (%d)", options.path, strerror(errno), errno);
        return EXIT_FAILURE;
	}
#ifdef DEBUG
if ( options.headeronly ) {
    	uint8_t buffer[sparsebundlefs_getblocksize(sparsebundlefr_data_ptr)];
    	uint64_t offset = 1024;
		sparsebundlefs_read(sparsebundlefr_data_ptr, buffer, sparsebundlefs_getblocksize(sparsebundlefr_data_ptr), offset);
		print_hex(buffer, 64, "Block 0");
    	exit(EXIT_SUCCESS);
    }
#endif

//syslog(LOG_DEBUG, "initialized %s, block size %zu", data.path, data.blocksize);
//syslog(LOG_DEBUG, "sizeof(off_t)=%zu", sizeof(off_t));

    struct fuse_operations sparsebundle_filesystem_operations = {};
    sparsebundle_filesystem_operations.getattr = sparsebundle_fuse_getattr;
    sparsebundle_filesystem_operations.open = sparsebundle_fuse_open;
   	sparsebundle_filesystem_operations.read = sparsebundle_fuse_read;
    sparsebundle_filesystem_operations.readdir = sparsebundle_fuse_readdir;
    sparsebundle_filesystem_operations.release = sparsebundle_fuse_release;
#ifdef DEBUG
{
    char cmd[2000];
    snprintf(cmd, sizeof(cmd), "umount %s", mountpoint);
    system(cmd);
}
#endif
    return fuse_main(args.argc, args.argv, &sparsebundle_filesystem_operations, sparsebundlefr_data_ptr);
}
