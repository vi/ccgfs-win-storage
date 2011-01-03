#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include "xl.h"
#include "xl_errno.c"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

enum {
	OO_READ      = 1 << 0,
	OO_WRITE     = 1 << 1,
	OO_RDWR      = (OO_READ | OO_WRITE),
	OO_ACCMODE   = OO_RDWR,
	OO_CREAT     = 1 << 2,
	OO_EXCL      = 1 << 3,
	OO_TRUNC     = 1 << 5,
	OO_APPEND    = 1 << 6,
};

/* x is always negative or zero */
int generic_errno(int x)
{
	if (x > 0)
		abort();
	if (x < -ARRAY_SIZE(arch_to_generic_table))
		return x;
	else
		return arch_to_generic_table[-x];
}

/* x is always negative or zero */
int arch_errno(int x)
{
	if (x > 0)
		abort();
	if (x < -ARRAY_SIZE(generic_to_arch_table))
		return x;
	else
		return generic_to_arch_table[-x];
}

unsigned int generic_openflags(unsigned int x)
{
	unsigned int fl = 0;
	switch (x & O_ACCMODE) {
		case O_RDONLY:
			fl = OO_READ;
			break;
		case O_WRONLY:
			fl = OO_WRITE;
			break;
		case O_RDWR:
			fl = OO_RDWR;
			break;
	}
	if (x & O_CREAT)     fl |= OO_CREAT;
	if (x & O_EXCL)      fl |= OO_EXCL;
	if (x & O_TRUNC)     fl |= OO_TRUNC;
	if (x & O_APPEND)    fl |= OO_APPEND;
	/* No encoding of O_LARGEFILE, will always enable */
	return fl;
}

unsigned int arch_openflags(unsigned int x)
{
	unsigned int fl = 0;
	switch (x & OO_ACCMODE) {
		case OO_READ:
			fl = O_RDONLY;
			break;
		case OO_WRITE:
			fl = O_WRONLY;
			break;
		case OO_RDWR:
			fl = O_RDWR;
			break;
	}
	if (x & OO_CREAT)     fl |= O_CREAT;
	if (x & OO_EXCL)      fl |= O_EXCL;
	if (x & OO_TRUNC)     fl |= O_TRUNC;
	if (x & OO_APPEND)    fl |= O_APPEND;
	return fl;
}
