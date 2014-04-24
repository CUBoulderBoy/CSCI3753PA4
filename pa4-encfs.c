// PA4, CSCI 3753, Written by Christopher Jordan with help
// from Jeremy Granger, Alex Beal, and Robert Werthman
// Filename: pa4-encfs.c
// Last modified: 23 April 2014

/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#define ENOATTR ENODATA
#endif

/* Actions needed for do_crypt function, see aes-crypt.h */
#define ENCRYPT 1
#define DECRYPT 0
#define PASS_THROUGH -1

/* Extended attribute definitions for use with encryption */
#define XATRR_ENCRYPTED_FLAG "user.pa4-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

/* These file suffixes are used for creating temp files*/
#define SUFFIXGETATTR ".getattr"
#define SUFFIXREAD ".read"
#define SUFFIXWRITE ".write"
#define SUFFIXCREATE ".create"

#include "aes-crypt.h"
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stddef.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#include <sys/types.h>
#include <stdlib.h>
#include <limits.h>
#endif


// Struct used by FUSE to get private path data
struct priv_data {
	char* rootdir;
	char* key;
};

// For access to private data of path
#define XMP_DATA ((struct priv_data *) fuse_get_context()->private_data)

/* 
 * Path are all relative to the root of the mounted filesystem. Thus, it
 * is neccesary to obain the mountpoint. Save it in main the use method to
 * consturct the path.
 */
static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, XMP_DATA->rootdir);
    
    //If the path is too long, then break
    strncat(fpath, path, PATH_MAX);
}

/*
 * Mostly uneccessary funtion, just pass through
 */
void *xmp_init()
{
	return XMP_DATA;
}


/* 
 * Function to create a temp file to hold the contents of
 * the path file for encryption or decryption
 * Code adapted from Alex Beal's "PA5" repo.
 */
char* tempfile(const char* path, const char* suffix)
{
    char* npath;
    int length = 0;
    
    length = strlen(path) + strlen(suffix) + 1;
    npath = malloc(sizeof(char) * length);
    if(npath == NULL){
        return NULL;
    }
    npath[0] = '\0';
    strcat(npath, path);
    strcat(npath, suffix);
    return npath;
}
    
/*
 * Function to get the attributes of the file
 */
static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
    int cryptic = PASS_THROUGH;
    ssize_t size = 0;
    char* tempstr = NULL;
	char fpath[PATH_MAX];
    
    time_t    atime;   /* time of last access */
    time_t    mtime;   /* time of last modification */
    time_t    tctime;   /* time of last status change */
    dev_t     t_dev;     /* ID of device containing file */
    ino_t     t_ino;     /* inode number */
    mode_t    mode;    /* protection */
    nlink_t   t_nlink;   /* number of hard links */
    uid_t     t_uid;     /* user ID of owner */
    gid_t     t_gid;     /* group ID of owner */
    dev_t     t_rdev;    /* device ID (if special file) */

	xmp_fullpath(fpath, path);
	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;
    
    //is it a regular file?
	if (S_ISREG(stbuf->st_mode)){
        
        // These file characteristics are passed through with the decrypted file
		atime = stbuf->st_atime;
		mtime = stbuf->st_mtime;
		tctime = stbuf->st_ctime;
		t_dev = stbuf->st_dev;
		t_ino = stbuf->st_ino;
		mode = stbuf->st_mode;
		t_nlink = stbuf->st_nlink;
		t_uid = stbuf->st_uid;
		t_gid = stbuf->st_gid;
		t_rdev = stbuf->st_rdev;
        
        // getxattr retrieves a file's attributes to determine whether to decrypt/encrypt
        size = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
        tempstr = malloc(sizeof(*tempstr) * (size));
        size = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tempstr, size);
        
        /* If the specified attribute doesn't exist or it's set to false */
		if (size < 0 || memcmp(tempstr, "false", 5) == 0){
			if(errno == ENOATTR){
				fprintf(stderr, "No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
			}
			//fprintf(stderr, "file is unencrypted, leaving cryptic as pass-through\n valsize is %zu\n", valsize);
			fprintf(stderr, "file is unencrypted, leaving cryptic as pass-through\n");
            
		} /* If the attribute exists and is true then we need to get size of decrypted file */
		else if (memcmp(tempstr, "true", 4) == 0){
			//fprintf(stderr, "file is encrypted, need to decrypt\nvalsize is %zu\n", valsize);
			fprintf(stderr, "file is encrypted, need to decrypt\n");
			cryptic = DECRYPT;
		}
        
        // Creating temp file for use with encrypting
        const char* tempf = tempfile(fpath, SUFFIXGETATTR);
        FILE *tmpff = fopen(tempf, "wb+");
        FILE *f = fopen(fpath, "rb");
        
        if(!do_crypt(f, tmpff, cryptic, XMP_DATA->key)){
            fprintf(stderr, "getattr do_crypt failed\n");
    	}
        
		fclose(f);
		fclose(tmpff);
        
		/* Retrieves size of decrypted file */
		res = lstat(tempf, stbuf);
		if (res == -1){
			return -errno;
		}
        
		/* Put info about file we did not want to change back into stat struct*/
		stbuf->st_atime = atime;
		stbuf->st_mtime = mtime;
		stbuf->st_ctime = tctime;
		stbuf->st_dev = t_dev;
		stbuf->st_ino = t_ino;
		stbuf->st_mode = mode;
		stbuf->st_nlink = t_nlink;
		stbuf->st_uid = t_uid;
		stbuf->st_gid = t_gid;
		stbuf->st_rdev = t_rdev;
        
		free(tempstr);
		remove(tempf);
	}
	return 0;
}

// Access File Attributes
static int xmp_access(const char *path, int mask)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

// Read Target of a Symbolic Link
static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

// Read Directory
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];

	(void) offset;
	(void) fi;

	xmp_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

// Create a File Node
static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

// Create New Directory
static int xmp_mkdir(const char *path, mode_t mode)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

// Remove a File
static int xmp_unlink(const char *path)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

// Remove a Directory
static int xmp_rmdir(const char *path)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

// Create a Symbolic Link
static int xmp_symlink(const char *from, const char *to)
{
	int res = 0;
	char fto[PATH_MAX];

	xmp_fullpath(fto, to);
	res = symlink(from, fto);
	if (res == -1)
		return -errno;

	return 0;
}

// Rename a File
static int xmp_rename(const char *from, const char *to)
{
	int res = 0;
	char newfrom[PATH_MAX];
	char newto[PATH_MAX];

	xmp_fullpath(newfrom, from);
	xmp_fullpath(newto, to);
	res = rename(newfrom, newto);
	if (res == -1)
		return -errno;

	return 0;
}

// Create a Hardlink to a File
static int xmp_link(const char *from, const char *to)
{
	int res = 0;
	char newfrom[PATH_MAX];
	char newto[PATH_MAX];

	xmp_fullpath(newfrom, from);
	xmp_fullpath(newto, to);
	res = link(newfrom, newto);
	if (res == -1)
		return -errno;

	return 0;
}

// Change Permission Bits of a File
static int xmp_chmod(const char *path, mode_t mode)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

// Change Owner and Group of a File
static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

// Change the Size of a File
static int xmp_truncate(const char *path, off_t size)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

// Change access and/or Modification Times of a File
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res = 0;
	struct timeval tv[2];
	char fpath[PATH_MAX];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	xmp_fullpath(fpath, path);
	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

// Open File Operation
static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res = 0;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

/* This function reads file contents into application window */
// This function was adapted from Alex Beal and Robert Wethman
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    
	(void)fi;
	int res = 0;
	int cryptic = PASS_THROUGH;
	ssize_t valsize = 0;
	char *tmpval = NULL;
    
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
    
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tmpval = malloc(sizeof(*tmpval)*(valsize));
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tmpval, valsize);
    
	fprintf(stderr, " Read: Xattr Value: %s\n", tmpval);
    
	/* If the specified attribute doesn't exist or it's set to false */
	if (valsize < 0 || memcmp(tmpval, "false", 5) == 0){
		if(errno == ENOATTR){
			fprintf(stderr, "Read: No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
		}
		fprintf(stderr, "Read: file is unencrypted, leaving cryptic as pass-through\n");
	}/* If the attribute exists and is true then we need to get size of decrypted file */
	else if (memcmp(tmpval, "true", 4) == 0){
		fprintf(stderr, "Read: file is encrypted, need to decrypt\n");
		cryptic = DECRYPT;
	}
    
	const char *tmpPath = tempfile(fpath, SUFFIXREAD);
	FILE *tmpFile = fopen(tmpPath, "wb+");
	FILE *f = fopen(fpath, "rb");
    
	fprintf(stderr, "Read: fpath: %s\ntmpPath: %s\n", fpath, tmpPath);
    
	if(!do_crypt(f, tmpFile, cryptic, XMP_DATA->key)){
        fprintf(stderr, "Read: do_crypt failed\n");
    }
    
    fseek(tmpFile, 0, SEEK_END);
    size_t tmpFilelen = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    
    fprintf(stderr, "Read: size given by read: %zu\nsize of tmpFile: %zu\nsize of offset: %zu\n", size, tmpFilelen, offset);
    
    /* Read the decrypted contents of original file to the application widow */
    res = fread(buf, 1, tmpFilelen, tmpFile);
    if (res == -1)
    	res = -errno;
    
	fclose(f);
	fclose(tmpFile);
	remove(tmpPath);
	free(tmpval);
    
	return res;
    
    
}

// Write contents to encrypted or unencrypted file
// This function was adapted from Alex Beal and Robert Wethman
static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
	(void) fi;
	(void) offset;
	int res = 0;
	int fd = 0;
	int cryptic = PASS_THROUGH;
	ssize_t valsize = 0;
	char *tmpval = NULL;
    
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
    
    
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tmpval = malloc(sizeof(*tmpval)*(valsize));
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tmpval, valsize);
    
	fprintf(stderr, " WRITE: Xattr Value: %s\n", tmpval);
    
	if (valsize < 0 || memcmp(tmpval, "false", 5) == 0){
		if(errno == ENOATTR){
			fprintf(stderr, "WRITE: No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
		}
		fprintf(stderr, "WRITE: file is unencrypted, leaving cryptic as pass-through\n");
	}/* If the attribute exists and is true then we need to get size of decrypted file */
	else if (memcmp(tmpval, "true", 4) == 0){
		fprintf(stderr, "WRITE: file is encrypted, need to decrypt\n");
		cryptic = DECRYPT;
	}
    
	fprintf(stderr, "cryptic is set to %d\n", cryptic);
    
	/* If the file to be written to is encrypted */
	if (cryptic == DECRYPT){
		fprintf(stderr, "WRITE: File to be written is encrypted\n");
        
		FILE *f = fopen(fpath, "rb+");
		const char *tmpPath = tempfile(fpath, SUFFIXWRITE);
		FILE *tmpFile = fopen(tmpPath, "wb+");
        
		fprintf(stderr, "path of original file %s\n", fpath);
        
		fseek(f, 0, SEEK_END);
		size_t original = ftell(f);
		fseek(f, 0, SEEK_SET);
		fprintf(stderr, "Size of original file %zu\n", original);
        
		fprintf(stderr, "Decrypting contents of original file to tmpFile for writing\n");
		if(!do_crypt(f, tmpFile, DECRYPT, XMP_DATA->key)){
            fprintf(stderr, "WRITE: do_crypt failed\n");
    	}
        
    	fseek(f, 0, SEEK_SET);
        
    	size_t tmpFilelen = ftell(tmpFile);
    	fprintf(stderr, "Size to be written to tmpFile %zu\n", size);
    	fprintf(stderr, "size of tmpFile %zu\n", tmpFilelen);
    	fprintf(stderr, "Writing to tmpFile\n");
        
    	res = fwrite(buf, 1, size, tmpFile);
    	if (res == -1)
			res = -errno;
        
		tmpFilelen = ftell(tmpFile);
		fprintf(stderr, "Size of tmpFile after write %zu\n", tmpFilelen);
        
		fseek(tmpFile, 0, SEEK_SET);
        
		fprintf(stderr, "Encrypting new contents of tmpFile into original file\n");
		if(!do_crypt(tmpFile, f, ENCRYPT, XMP_DATA->key)){
            fprintf(stderr, "WRITE: do_crypt failed\n");
		}
        
		fclose(f);
		fclose(tmpFile);
		remove(tmpPath);
    	
	}/* If the file to be written to is unencrypted */
	else if (cryptic == PASS_THROUGH){
		fprintf(stderr, "File to be written is unencrypted");
        
		fd = open(fpath, O_WRONLY);
		if (fd == -1)
			return -errno;
        
		res = pwrite(fd, buf, size, offset);
		if (res == -1)
			res = -errno;
        
		close(fd);
   	}
   	
	free(tmpval);
	return res;
}

// Get File System Statistics
static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    
    
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
    
    
    (void) fi;
    (void) mode;
    
	FILE *f = fopen(fpath, "wb+");
    
	fprintf(stderr, "CREATE: fpath: %s\n", fpath);
    
	/* It is okay to encrypt a file into itself as long as it's empty
     *	otherwise the contents of the file would be erased.
     */
    
	if(!do_crypt(f, f, ENCRYPT, XMP_DATA->key)){
		fprintf(stderr, "Create: do_crypt failed\n");
    }
    
	fprintf(stderr, "Create: encryption done correctly\n");
    
	fclose(f);
    
	if(setxattr(fpath, XATRR_ENCRYPTED_FLAG, ENCRYPTED, 4, 0)){
    	fprintf(stderr, "error setting xattr of file %s\n", fpath);
    	return -errno;
   	}
   	fprintf(stderr, "Create: file xatrr correctly set %s\n", fpath);
    
    
    return 0;
}

// Release and Open File
static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

// Synchronize File Contents
static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
// Set Extended Attributes
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

// Get Extended Attributes
static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

// List Extended Attributes
static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

// Remove Extended Attributes
static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];

	xmp_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.init		= xmp_init,
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

// Function that prints usage format in case user incorrectly
// enters command line arguments
void usage() 
{
	// Prints usage line if arguments not properly supplied
	printf("./pa4-encfs <key phrase> <rootdir> <mountpoint>\n");
	abort();
}

// Main Function, user-stated directory/mount point used here
int main(int argc, char *argv[])
{
	// Ensures correct amount of arguments are passed to pa4-encfs
	// at command line
	if(argc < 4)
	{
		usage();
	}

	struct priv_data* myargs = malloc(sizeof(struct priv_data));
	if (myargs == NULL) {
	perror("main calloc");
	abort();
    }

	// Pull the rootdir and encryption key out of the argument 
	// list and save it in private data struct
	myargs->rootdir = realpath(argv[2], NULL);
    myargs->key = argv[1];
	argv[1] = argv[3];
    argv[2] = argv[4];
    argv[3] = NULL;
	argv[4] = NULL;
	argc -= 2;
	
	umask(0);
	// turn over control to fuse
	return fuse_main(argc, argv, &xmp_oper, myargs);
}
