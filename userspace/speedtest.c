#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
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

static void simple_memcpy(void *dst_, void const *src_, size_t len)
{
	for (;; ) {
		typedef uintmax_t	mem_t;

		mem_t		*dst = dst_;
		mem_t const	*src = src_;

		if ((uintptr_t)dst % sizeof *dst != 0 ||
		    (uintptr_t)src % sizeof *src != 0)
			break;

		while (len >= sizeof *dst) {
			*dst++ = *src++;
			len   -= sizeof *dst;
		}

		dst_ = dst;
		src_ = src;

		break;
	}

	for (;; ) {
		typedef uint8_t	mem_t;

		mem_t		*dst = dst_;
		mem_t const	*src = src_;

		if ((uintptr_t)dst % sizeof *dst != 0 ||
		    (uintptr_t)src % sizeof *src != 0)
			break;

		while (len >= sizeof *dst) {
			*dst++ = *src++;
			len   -= sizeof *dst;
		}

		dst_ = dst;
		src_ = src;

		break;
	}
}

static void speed_test(struct buf const *buf, void *tmp_buf, size_t cnt)
{
	static char const * const	MODE_STR[] = {
		[0] = "simple_memcpy()",
		[1] = "memcpy()",
		[2] = "ldm+stm",
		[3] = "ldm"
	};
	static bool			mode_shown = false;
	struct timespec	tm_a;
	struct timespec	tm_b;
	struct rusage	usage_a;
	struct rusage	usage_b;
	char		printf_buf[64];
	size_t		orig_cnt = cnt;
	int		cp_mode = 1;

	if (getenv("MODE"))
		cp_mode = atoi(getenv("MODE"));

	if (!mode_shown) {
		printf("==== %s =====\n", MODE_STR[cp_mode]);
		mode_shown = true;
	}

	getrusage(RUSAGE_SELF, &usage_a);
	clock_gettime(CLOCK_MONOTONIC, &tm_a);

	__asm__("" ::: "memory");

	while (cnt > 0) {
		unsigned int	tmp_len = buf->len;
		void const	*in_addr = buf->mem;
		void 		*out_addr = tmp_buf;

		switch (cp_mode) {
		case 0:
			simple_memcpy(out_addr, in_addr, tmp_len);
			__asm__("" ::: "memory");
			break;

		case 1:
			memcpy(out_addr, in_addr, tmp_len);
			__asm__("" ::: "memory");
			break;

		case 2:
			/* TODO: this is broken for buf->len < 32 and
			 * unaligned addresses */
			__asm__ __volatile__(
				"1:\n"
				"pld	[%[addr], #192]\n"
				"ldm	%[addr]!,{r0-r7}\n"
				"subs	%[cnt], #32\n"
				"stm	%[out]!,{r0-r7}\n"
				"bgt	1b\n"
				: [cnt]  "+r" (tmp_len),
				  [addr] "+r" (in_addr),
				  [out]  "+r" (out_addr)
				:
				: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
				  "memory");
			break;

		case 3:
			/* TODO: this is broken for buf->len < 32 and
			 * unaligned addresses */
			__asm__ __volatile__(
				"1:\n"
				"pld	[%[addr], #128]\n"
				"ldm	%[addr]!,{r0-r7}\n"
				"subs	%[cnt], #32\n"
				"bgt	1b\n"
				: [cnt]  "+r" (tmp_len),
				  [addr] "+r" (in_addr)
				:
				: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
				  "memory");
		}

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
