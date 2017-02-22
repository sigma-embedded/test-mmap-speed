#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>

#define MMAP_IOCTL_MODE_WRITEBACK	_IO('M', 0)
#define MMAP_IOCTL_MODE_WRITETHROUGH	_IO('M', 1)
#define MMAP_IOCTL_MODE_COHERENT	_IO('M', 2)
#define MMAP_IOCTL_MODE_WRITECOMBINE	_IO('M', 3)

struct buf {
	void		*mem;
	size_t		len;
	char const	*type;
};

static struct buf *alloc_buf(int fd, size_t sz, struct buf *buf, unsigned int ioc)
{
	int		rc;

	rc = ioctl(fd, ioc);
	if (rc < 0)
		abort();

	buf->mem = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
	if (buf->mem == MAP_FAILED)
		abort();

	buf->len = sz;

	switch (ioc) {
	case MMAP_IOCTL_MODE_WRITEBACK:
		buf->type = "writeback";
		break;
	case MMAP_IOCTL_MODE_WRITETHROUGH:
		buf->type = "writethrough";
		break;
	case MMAP_IOCTL_MODE_COHERENT:
		buf->type = "coherent";
		break;
	case MMAP_IOCTL_MODE_WRITECOMBINE:
		buf->type = "writecombine";
		break;
	}

	return buf+1;
}

static uint64_t timespec_to_ns(struct timespec const *t)
{
	uint64_t	res = t->tv_sec;

	res *= 1000000000ull;
	res += t->tv_nsec;

	return res;
}

static char const *fmt_ns(char *buf, uint64_t ns)
{
	sprintf(buf, "%ld.%09ld",
		(unsigned long)(ns / 1000000000ull),
		(unsigned long)(ns % 1000000000ull));

	return buf;
}

static char const *fmt_time_delta(char *buf,
				  struct timespec const *end,
				  struct timespec const *start)
{
	return fmt_ns(buf, timespec_to_ns(end) - timespec_to_ns(start));
}

static void speed_test(struct buf const *buf, void *tmp_buf, size_t cnt)
{
	struct timespec	tm_a;
	struct timespec	tm_b;
	struct rusage	usage_a;
	struct rusage	usage_b;
	char		printf_buf[64];
	size_t		orig_cnt = cnt;


	getrusage(RUSAGE_SELF, &usage_a);
	clock_gettime(CLOCK_MONOTONIC, &tm_a);

	while (cnt > 0) {
		__asm__("" ::: "memory");
		memcpy(tmp_buf, buf->mem, buf->len);
		__asm__("" ::: "memory");

		--cnt;
	}

	clock_gettime(CLOCK_MONOTONIC, &tm_b);
	getrusage(RUSAGE_SELF, &usage_b);

	printf("%14s: copied %zu times %zu bytes in %ss, %ld/%ld page faults, %ld/%ld ctx switches \n",
	       buf->type, orig_cnt, buf->len,
	       fmt_time_delta(printf_buf, &tm_b, &tm_a),
	       usage_b.ru_minflt - usage_a.ru_minflt,
	       usage_b.ru_majflt - usage_a.ru_majflt,
	       usage_b.ru_nvcsw - usage_a.ru_nvcsw,
	       usage_b.ru_nivcsw - usage_a.ru_nivcsw);
}

int main(int argc, char *argv[])
{
	int		fd =  open("/dev/mmap-test", O_RDWR | O_NOCTTY);
	size_t		size = strtoul(argv[1], NULL, 0);

	void		*tmp_buf;
	struct buf	bufs[5];
	struct buf	*b = &bufs[0];
	size_t		i;

	system("echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");

	tmp_buf = malloc(size + 0x10000);
	if (!tmp_buf)
		abort();

	b = alloc_buf(fd, size, b, MMAP_IOCTL_MODE_WRITETHROUGH);
	b = alloc_buf(fd, size, b, MMAP_IOCTL_MODE_WRITECOMBINE);
	b = alloc_buf(fd, size, b, MMAP_IOCTL_MODE_WRITEBACK);
	b = alloc_buf(fd, size, b, MMAP_IOCTL_MODE_COHERENT);

	b->mem = malloc(size);
	b->type = "malloc()";
	b->len = size;
	memset(b->mem, 0, size);

	++b;

	system("cat /sys/kernel/debug/kernel_page_tables");

	close(fd);

	memset(tmp_buf, 0, size);
	__asm__("" ::: "memory");

	for (i = 0; i < b - &bufs[0]; ++i)
		speed_test(&bufs[i], tmp_buf, atoi(argv[2]));
}
