/*
 *	CC Network Filesystem (ccgfs)
 *	Storage Engine
 *
 *	Copyright © Jan Engelhardt <jengelh [at] medozas de>, 2007 - 2008
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 *
 *	Hacked by Vitaly "_Vi" Shukela to be buildable with i586-mingw32msvc-gcc
 */
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE 1
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#ifndef WIN32
    #include <arpa/inet.h>
    #include <sys/socket.h>
#else
    #include <winsock2.h>
#endif

#ifndef O_BINARY
    #define O_BINARY 0
#endif

#include "ccgfs.h"
#include "packet.h"

#define b_path(dest, src) /* build path */ \
	(snprintf(dest, sizeof(dest), "%s%s", root_dir, (src)) >= \
	          sizeof(dest))
#define perror(s) perror("ccgfs-storage: " s)

enum {
	LOCALFS_SUCCESS = 0,
	LOCALFS_STOP,
};

typedef int (*localfs_func_t)(int, struct lo_packet *);

static __attribute__((pure)) const char *at(const char *in)
{
	if (*in != '/')
		abort();
	if (in[1] == '\0')
		return ".";
	return in + 1;
}

static int localfs_chmod(int fd, struct lo_packet *rq)
{                
        const char *rq_path = pkt_shift_s(rq);
	mode_t rq_mode      = pkt_shift_32(rq);    

        (void)rq_path;
	(void)rq_mode;

	// Silently fail

	return LOCALFS_SUCCESS;
}

static int localfs_chown(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	int rq_uid        = pkt_shift_32(rq);
	int rq_gid        = pkt_shift_32(rq);             

        (void)rq_path;
	(void)rq_uid;
	(void)rq_gid;

	// Silently fail
                            

        return LOCALFS_SUCCESS;
}

static int localfs_create(int fd, struct lo_packet *rq)
{
	const char *rq_path   = pkt_shift_s(rq);
	unsigned int rq_flags = pkt_shift_32(rq);
	mode_t rq_mode        = pkt_shift_32(rq);
	struct lo_packet *rp;
	int ret;

	ret = open(at(rq_path), arch_openflags(rq_flags)|O_BINARY, rq_mode);
	if (ret < 0)
		return -errno;

	rp = pkt_init(CCGFS_CREATE_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static struct lo_packet *getattr_copy_stor(const struct stat *sb)
{
	struct lo_packet *rp;

	rp = pkt_init(CCGFS_GETATTR_RESPONSE, 7 * PV_64 + 5 * PV_32);
	if (rp == NULL)
		return NULL;

	unsigned long long int fake_st_blksize=1024;
	unsigned long long int fake_st_blocks=sb->st_size/1024+1;

	pkt_push_64(rp, sb->st_ino);
	pkt_push_32(rp, sb->st_mode);
	pkt_push_32(rp, sb->st_nlink);
	pkt_push_32(rp, sb->st_uid);
	pkt_push_32(rp, sb->st_gid);
	pkt_push_32(rp, sb->st_rdev);
	pkt_push_64(rp, sb->st_size);
	pkt_push_64(rp, fake_st_blksize);
	pkt_push_64(rp, fake_st_blocks);
	pkt_push_64(rp, sb->st_atime);
	pkt_push_64(rp, sb->st_mtime);
	pkt_push_64(rp, sb->st_ctime);
	return rp;
}

static int localfs_fgetattr(int fd, struct lo_packet *rq)
{
	int rq_fd = pkt_shift_32(rq);
	struct stat sb;

	if (fstat(rq_fd, &sb) < 0)
		return -errno;

	pkt_send(fd, getattr_copy_stor(&sb));
	return LOCALFS_STOP;
}

static int localfs_fsync(int fd, struct lo_packet *rq)
{                  
	int rq_fd              = pkt_shift_32(rq);
	unsigned int data_only = pkt_shift_32(rq);     

        (void)rq_fd;
	(void)data_only;

	// silently ignore

	return LOCALFS_SUCCESS;
}

static int localfs_ftruncate(int fd, struct lo_packet *rq)
{
	int rq_fd    = pkt_shift_32(rq);
	off_t rq_off = pkt_shift_64(rq);

	if (ftruncate(rq_fd, rq_off) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_getattr(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct stat sb;

	if (stat(at(rq_path), &sb) < 0)
		return -errno;

	pkt_send(fd, getattr_copy_stor(&sb));
	return LOCALFS_STOP;
}

static int localfs_getxattr(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);

	(void)rq_path;
	    
	return -ENOSYS;
}

static int localfs_link(int fd, struct lo_packet *rq)
{               
	const char *rq_oldpath = pkt_shift_s(rq);
	const char *rq_newpath = pkt_shift_s(rq);  

	(void)rq_oldpath;
	(void)rq_newpath;

	return -ENOSYS;
}

static int localfs_listxattr(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	size_t rq_size      = pkt_shift_64(rq);      

	(void)rq_path;
	(void)rq_size;

	return -ENOSYS;
}

static int localfs_mkdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	mode_t rq_mode      = pkt_shift_32(rq);

	(void)rq_mode;

	#ifdef WIN32
	if (mkdir(at(rq_path)) < 0)
	#else
	if (mkdir(at(rq_path), rq_mode) < 0)
	#endif
	
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_mknod(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	mode_t rq_mode      = pkt_shift_32(rq);
	dev_t rq_rdev       = pkt_shift_32(rq);         

	(void)rq_path;
	(void)rq_mode;
	(void)rq_rdev;

	return -ENOSYS;
}

static int localfs_open(int fd, struct lo_packet *rq)
{
	const char *rq_path   = pkt_shift_s(rq);
	unsigned int rq_flags = pkt_shift_32(rq);
	struct lo_packet *rp;
	int ret;

	ret = open(at(rq_path), arch_openflags(rq_flags)|O_BINARY);
	if (ret < 0)
		return -errno;

	rp = pkt_init(CCGFS_OPEN_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static int localfs_opendir_access(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct stat sb;

	if (stat(at(rq_path), &sb) < 0)
		return -errno;
	if (!S_ISDIR(sb.st_mode))
		return -ENOTDIR;
	return LOCALFS_SUCCESS;
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t retval ;
    off_t saved_pos = lseek (fd, 0, SEEK_CUR);

    lseek (fd, offset, SEEK_SET);
    retval = read (fd, buf, count);
    lseek (fd, saved_pos, SEEK_SET);

    return retval;    
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    ssize_t retval ;
    off_t saved_pos = lseek (fd, 0, SEEK_CUR);

    lseek (fd, offset, SEEK_SET);
    retval = write (fd, buf, count);
    lseek (fd, saved_pos, SEEK_SET);

    return retval;    
}


static int localfs_read(int fd, struct lo_packet *rq)
{
	int rq_fd       = pkt_shift_32(rq);
	size_t rq_size  = pkt_shift_64(rq);
	off_t rq_offset = pkt_shift_64(rq);

	struct lo_packet *rp;
	ssize_t ret;
	char *buf;

	buf = malloc(rq_size);
	if (buf == NULL)
		return -EIO;
	ret = pread(rq_fd, buf, rq_size, rq_offset);
	if (ret < 0) {
		if (errno != ESPIPE) {
			free(buf);
			return -errno;
		}
		ret = read(rq_fd, buf, rq_size);
	}
	if (ret < 0) {
		free(buf);
		return -errno;
	}

	rp = pkt_init(CCGFS_READ_RESPONSE, 2 * PV_STRING);
	pkt_push_64(rp, ret);
	pkt_push(rp, buf, ret, PT_DATA);
	pkt_send(fd, rp);
	free(buf);
	return LOCALFS_STOP;
}

static int localfs_readdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct dirent *dentry;
	struct lo_packet *rp;
	DIR *ptr;

	if ((ptr = opendir(at(rq_path))) == NULL)
		return -errno;

	while ((dentry = readdir(ptr)) != NULL) {
		rp = pkt_init(CCGFS_READDIR_RESPONSE,
		              PV_64 + PV_32 + PV_STRING);
		long long int d_ino = dentry->d_ino;
		if(d_ino==0) {
		    /* hack */
		    d_ino = 1;
		}
		pkt_push_64(rp, d_ino);
		pkt_push_32(rp, 0);
		pkt_push_s(rp, dentry->d_name);
		pkt_send(fd, rp);
	}

	closedir(ptr);
	return LOCALFS_SUCCESS;
}

static int localfs_readlink(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
        (void) rq_path;

	return -EINVAL;
}

static int localfs_release(int fd, struct lo_packet *rq)
{
	if (close(pkt_shift_32(rq)) < 0)
		return -errno;
	return LOCALFS_SUCCESS;
}

static int localfs_removexattr(int fd, struct lo_packet *rq)
{                  
	const char *rq_path = pkt_shift_s(rq);
	const char *rq_name = pkt_shift_s(rq);   

	(void)rq_path;
	(void)rq_name;

	return -ENOSYS;
}

static int localfs_rename(int fd, struct lo_packet *rq)
{
	const char *rq_oldpath = pkt_shift_s(rq);
	const char *rq_newpath = pkt_shift_s(rq);

	if (rename(at(rq_oldpath), at(rq_newpath)) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_rmdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);

	if (rmdir(at(rq_path)) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_setxattr(int fd, struct lo_packet *rq)
{
	const char *rq_path  = pkt_shift_s(rq);
	const char *rq_name  = pkt_shift_s(rq);
	const char *rq_value = pkt_shift_s(rq);
	size_t rq_size       = pkt_shift_64(rq);
	unsigned int flags   = pkt_shift_32(rq);    

	(void)rq_path;
	(void)rq_name;
	(void)rq_value;
	(void)rq_size;
	(void)flags;

	return -ENOSYS;
}

static int localfs_symlink(int fd, struct lo_packet *rq)
{                
	const char *rq_oldpath = pkt_shift_s(rq);
	const char *rq_newpath = pkt_shift_s(rq);  

	(void) rq_oldpath;
	(void) rq_newpath;

	return -ENOSYS;
}

static int localfs_statfs(int fd, struct lo_packet *rq)
{
	return -ENOSYS;
}

static int localfs_truncate(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	off_t rq_off        = pkt_shift_64(rq);

        int fd2 = open(at(rq_path), O_WRONLY|O_BINARY);
	if(fd2<0) {
		return -errno;
	}

	if (ftruncate(fd2, rq_off) < 0)
		return -errno;

	close(fd2);

	return LOCALFS_SUCCESS;
}

static int localfs_unlink(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);

	if (unlink(at(rq_path)) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_utimens(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	
        (void)rq_path;

        /* Fail silently */

	return 0;
}

static int localfs_write(int fd, struct lo_packet *rq)
{
	int rq_fd        = pkt_shift_32(rq);
	size_t size      = pkt_shift_64(rq);
	off_t offset     = pkt_shift_64(rq);
	const char *data = pkt_shift_s(rq);

	struct lo_packet *rp;
	ssize_t ret;

	ret = pwrite(rq_fd, data, size, offset);
	if (ret < 0) {
		if (errno != ESPIPE)
			return -errno;
		ret = write(rq_fd, data, size);
	}
	if (ret < 0)
		return -errno;

	rp = pkt_init(CCGFS_ERRNO_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static const localfs_func_t localfs_func_array[] = {
	[CCGFS_CHMOD_REQUEST]       = localfs_chmod,
	[CCGFS_CHOWN_REQUEST]       = localfs_chown,
	[CCGFS_CREATE_REQUEST]      = localfs_create,
	[CCGFS_FGETATTR_REQUEST]    = localfs_fgetattr,
	[CCGFS_FSYNC_REQUEST]       = localfs_fsync,
	[CCGFS_FTRUNCATE_REQUEST]   = localfs_ftruncate,
	[CCGFS_GETATTR_REQUEST]     = localfs_getattr,
	[CCGFS_GETXATTR_REQUEST]    = localfs_getxattr,
	[CCGFS_LINK_REQUEST]        = localfs_link,
	[CCGFS_LISTXATTR_REQUEST]   = localfs_listxattr,
	[CCGFS_MKDIR_REQUEST]       = localfs_mkdir,
	[CCGFS_MKNOD_REQUEST]       = localfs_mknod,
	[CCGFS_OPEN_REQUEST]        = localfs_open,
	[CCGFS_OPENDIR_REQUEST]     = localfs_opendir_access,
	[CCGFS_READ_REQUEST]        = localfs_read,
	[CCGFS_READDIR_REQUEST]     = localfs_readdir,
	[CCGFS_READLINK_REQUEST]    = localfs_readlink,
	[CCGFS_RELEASE_REQUEST]     = localfs_release,
	[CCGFS_REMOVEXATTR_REQUEST] = localfs_removexattr,
	[CCGFS_RENAME_REQUEST]      = localfs_rename,
	[CCGFS_RMDIR_REQUEST]       = localfs_rmdir,
	[CCGFS_SETXATTR_REQUEST]    = localfs_setxattr,
	[CCGFS_STATFS_REQUEST]      = localfs_statfs,
	[CCGFS_SYMLINK_REQUEST]     = localfs_symlink,
	[CCGFS_TRUNCATE_REQUEST]    = localfs_truncate,
	[CCGFS_UNLINK_REQUEST]      = localfs_unlink,
	[CCGFS_UTIMENS_REQUEST]     = localfs_utimens,
	[CCGFS_WRITE_REQUEST]       = localfs_write,
};

static int localfs_setfsid(struct lo_packet *rq)
{
	int uid = pkt_shift_32(rq);
	int gid = pkt_shift_32(rq);
	return -ENOSYS;
}

static void handle_packet(int fd, struct lo_packet *rq)
{
	struct ccgfs_pkt_header *hdr;
	struct lo_packet *rp;
	localfs_func_t lf;
	int ret;
        
	(void)localfs_setfsid(rq);

	ret = -EIO;
	hdr = rq->data;
	lf  = localfs_func_array[hdr->opcode];
	if (lf != NULL)
		ret = (*lf)(fd, rq);

	if (ret <= 0) {
		rp = pkt_init(CCGFS_ERRNO_RESPONSE, PV_32);
		pkt_push_32(rp, generic_errno(ret));
		pkt_send(fd, rp);
	}
}

static void send_fsinfo(int fd)
{
	struct lo_packet *rp;
        
	char cwd[65536];
	getcwd(cwd,65536);

	rp = pkt_init(CCGFS_FSINFO, PV_STRING);
	pkt_push_s(rp, cwd);
	pkt_send(fd, rp);
}

int main(int argc, const char **argv)
{
	if(argc<3) {
	    fprintf(stderr, "Usage: ccgfs-storage.exe IP_addr port\nIt will listen that socket and accept one client\n");
	    exit(2);
	}
	#ifdef WIN32
	    WSADATA wsaData;
	    int iResult = WSAStartup( MAKEWORD(2,2), &wsaData );
	    if ( iResult != NO_ERROR ) {
		fprintf(stderr,"Error at WSAStartup()\n");
		exit(1);
	    }
	#endif

	const char* bind_ip = argv[1];
	int bind_port = atoi(argv[2]);

	int ss = socket(PF_INET, SOCK_STREAM, 0);
	if (ss <= 0) {
	    perror("socket");
	    exit(1);
	}

	#ifndef WIN32
	int opt = 1;
	setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
	#endif

        struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = PF_INET;
	sa.sin_port = htons(bind_port);
	#ifdef WIN32
	sa.sin_addr.S_un.S_addr = inet_addr(bind_ip);
	#else
	inet_aton(bind_ip, &sa.sin_addr);
	#endif
	if (-1 == bind(ss, (struct sockaddr *) &sa, sizeof sa)) {
	    #ifdef WIN32
	    fprintf(stderr, "WLE=%d\n", WSAGetLastError());
	    #endif
	    perror("bind");
	    close(ss);
	    exit(1);
	}
	if (-1 == listen(ss, 0)) {
	    #ifdef WIN32
	    fprintf(stderr, "WLE=%d\n", WSAGetLastError());
	    #endif
	    perror("listen");
	    close(ss);
	    exit(1);
	}

	/* Accepting the client socket */
	struct sockaddr_in da; 
	size_t len = sizeof sa;
	int client = accept(ss, (struct sockaddr *) &sa, &len);
	if (client <= 0) {
	    perror("accept");
	    return;
	}

	struct lo_packet *rq;
	umask(0);
	send_fsinfo(client);
         
	while (true) {
		rq = pkt_recv(client);
		if (rq == NULL)
			break;
		handle_packet(client, rq);
		pkt_destroy(rq);
	}

	return EXIT_SUCCESS;
}
