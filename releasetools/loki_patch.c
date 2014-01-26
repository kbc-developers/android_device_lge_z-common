/*
 * loki_patch
 *
 * A utility to patch unsigned boot and recovery images to make
 * them suitable for booting on the AT&T/Verizon Samsung
 * Galaxy S4, Galaxy Stellar, and various locked LG devices
 *
 * by Dan Rosenberg (@djrbliss)
 *
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define VERSION "2.1"

#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512

struct boot_img_hdr {
	unsigned char magic[BOOT_MAGIC_SIZE];
	unsigned kernel_size;	/* size in bytes */
	unsigned kernel_addr;	/* physical load addr */
	unsigned ramdisk_size;	/* size in bytes */
	unsigned ramdisk_addr;	/* physical load addr */
	unsigned second_size;	/* size in bytes */
	unsigned second_addr;	/* physical load addr */
	unsigned tags_addr;		/* physical addr for kernel tags */
	unsigned page_size;		/* flash page size we assume */
	unsigned dt_size;		/* device_tree in bytes */
	unsigned unused;		/* future expansion: should be 0 */
	unsigned char name[BOOT_NAME_SIZE];	/* asciiz product name */
	unsigned char cmdline[BOOT_ARGS_SIZE];
	unsigned id[8];			/* timestamp / checksum / sha1 / etc */
};

struct loki_hdr {
	unsigned char magic[4];		/* 0x494b4f4c */
	unsigned int recovery;		/* 0 = boot.img, 1 = recovery.img */
	unsigned char build[128];	/* Build number */

	unsigned int orig_kernel_size;
	unsigned int orig_ramdisk_size;
	unsigned int ramdisk_addr;
};

struct target {
	char *vendor;
	char *device;
	char *build;
	unsigned long check_sigs;
	unsigned long hdr;
	int lg;
};

struct target targets[] = {
        {
                .vendor = "KT",
                .device = "LG G Flex",
                .build = "F340K",
                .check_sigs = 0xf8124a4,
                .hdr = 0xf8b6440,
                .lg = 1,
        },
};

#define PATTERN1 "\xf0\xb5\x8f\xb0\x06\x46\xf0\xf7"
#define PATTERN2 "\xf0\xb5\x8f\xb0\x07\x46\xf0\xf7"
#define PATTERN3 "\x2d\xe9\xf0\x41\x86\xb0\xf1\xf7"
#define PATTERN4 "\x2d\xe9\xf0\x4f\xad\xf5\xc6\x6d"
#define PATTERN5 "\x2d\xe9\xf0\x4f\xad\xf5\x21\x7d"
#define PATTERN6 "\x2d\xe9\xf0\x4f\xf3\xb0\x05\x46"

#define ABOOT_BASE_SAMSUNG 0x88dfffd8
#define ABOOT_BASE_LG 0x88efffd8
#define ABOOT_BASE_G2 0xf7fffd8

unsigned char patch[] =
"\xfe\xb5"
"\x0d\x4d"
"\xd5\xf8"
"\x88\x04"
"\xab\x68"
"\x98\x42"
"\x12\xd0"
"\xd5\xf8"
"\x90\x64"
"\x0a\x4c"
"\xd5\xf8"
"\x8c\x74"
"\x07\xf5\x80\x57"
"\x0f\xce"
"\x0f\xc4"
"\x10\x3f"
"\xfb\xdc"
"\xd5\xf8"
"\x88\x04"
"\x04\x49"
"\xd5\xf8"
"\x8c\x24"
"\xa8\x60"
"\x69\x61"
"\x2a\x61"
"\x00\x20"
"\xfe\xbd"
"\xff\xff\xff\xff"
"\xee\xee\xee\xee";

int patch_shellcode(unsigned int header, unsigned int ramdisk)
{

	int i, found_header, found_ramdisk;
	unsigned int *ptr;

	found_header = 0;
	found_ramdisk = 0;

	for (i = 0; i < sizeof(patch); i++) {
		ptr = (unsigned int *)&patch[i];
		if (*ptr == 0xffffffff) {
			*ptr = header;
			found_header = 1;
		}

		if (*ptr == 0xeeeeeeee) {
			*ptr = ramdisk;
			found_ramdisk = 1;
		}
	}

	if (found_header && found_ramdisk)
		return 0;

	return -1;
}

int main(int argc, char **argv)
{

	int ifd, ofd, aboot_fd, pos, i, recovery, offset, fake_size;
	unsigned int orig_ramdisk_size, orig_kernel_size, page_kernel_size, page_ramdisk_size, page_size, page_mask;
	unsigned long target, aboot_base;
	void *orig, *aboot, *ptr;
	struct target *tgt;
	struct stat st;
	struct boot_img_hdr *hdr;
	struct loki_hdr *loki_hdr;
	char *buf;

	if (argc != 5) {
		printf("Usage: %s [boot|recovery] [aboot.img] [in.img] [out.lok]\n", argv[0]);
		return 1;
	}

	printf("[+] loki_patch v%s\n", VERSION);

	if (!strcmp(argv[1], "boot")) {
		recovery = 0;
	} else if (!strcmp(argv[1], "recovery")) {
		recovery = 1;
	} else {
		printf("[+] First argument must be \"boot\" or \"recovery\".\n");
		return 1;
	}

	/* Open input files */
	aboot_fd = open(argv[2], O_RDONLY);
	if (aboot_fd < 0) {
		printf("[-] Failed to open %s for reading.\n", argv[2]);
		return 1;
	}

	ifd = open(argv[3], O_RDONLY);
	if (ifd < 0) {
		printf("[-] Failed to open %s for reading.\n", argv[3]);
		return 1;
	}

	ofd = open(argv[4], O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (ofd < 0) {
		printf("[-] Failed to open %s for writing.\n", argv[4]);
		return 1;
	}

	/* Find the signature checking function via pattern matching */
	if (fstat(aboot_fd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	aboot = mmap(0, (st.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
	if (aboot == MAP_FAILED) {
		printf("[-] Failed to mmap aboot.\n");
		return 1;
	}

	target = 0;

	for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
		if (!memcmp(ptr, PATTERN1, 8) ||
			!memcmp(ptr, PATTERN2, 8) ||
			!memcmp(ptr, PATTERN3, 8)) {

			aboot_base = ABOOT_BASE_SAMSUNG;
			target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
			break;
		}

		if (!memcmp(ptr, PATTERN4, 8)) {

			aboot_base = ABOOT_BASE_LG;
			target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
			break;
		}

		if (!memcmp(ptr, PATTERN5, 8)) {

			aboot_base = ABOOT_BASE_G2;
			target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
			break;
		}
	}

	/* Do a second pass for the second LG pattern. This is necessary because
	 * apparently some LG models have both LG patterns, which throws off the
	 * fingerprinting. */

	if (!target) {
		for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
			if (!memcmp(ptr, PATTERN6, 8)) {

				aboot_base = ABOOT_BASE_LG;
				target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
				break;
			}
		}
	}

	if (!target) {
		printf("[-] Failed to find function to patch.\n");
		return 1;
	}

	tgt = NULL;

	for (i = 0; i < (sizeof(targets)/sizeof(targets[0])); i++) {
		if (targets[i].check_sigs == target) {
			tgt = &targets[i];
			break;
		}
	}

	if (!tgt) {
		printf("[-] Unsupported aboot image.\n");
		return 1;
	}

	printf("[+] Detected target %s %s build %s\n", tgt->vendor, tgt->device, tgt->build);

	/* Map the original boot/recovery image */
	if (fstat(ifd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ|PROT_WRITE, MAP_PRIVATE, ifd, 0);
	if (orig == MAP_FAILED) {
		printf("[-] Failed to mmap input file.\n");
		return 1;
	}

	hdr = orig;
	loki_hdr = orig + 0x400;

	if (!memcmp(loki_hdr->magic, "LOKI", 4)) {
		printf("[-] Input file is already a Loki image.\n");

		/* Copy the entire file to the output transparently */
		if (write(ofd, orig, st.st_size) != st.st_size) {
			printf("[-] Failed to copy Loki image.\n");
			return 1;
		}

		printf("[+] Copied Loki image to %s.\n", argv[4]);

		return 0;
	}

	/* Set the Loki header */
	memcpy(loki_hdr->magic, "LOKI", 4);
	loki_hdr->recovery = recovery;
	strncpy(loki_hdr->build, tgt->build, sizeof(loki_hdr->build) - 1);

	page_size = hdr->page_size;
	page_mask = hdr->page_size - 1;

	orig_kernel_size = hdr->kernel_size;
	orig_ramdisk_size = hdr->ramdisk_size;

	printf("[+] Original kernel address: %.08x\n", hdr->kernel_addr);
	printf("[+] Original ramdisk address: %.08x\n", hdr->ramdisk_addr);

	/* Store the original values in unused fields of the header */
	loki_hdr->orig_kernel_size = orig_kernel_size;
	loki_hdr->orig_ramdisk_size = orig_ramdisk_size;
	loki_hdr->ramdisk_addr = hdr->kernel_addr + ((hdr->kernel_size + page_mask) & ~page_mask);

	if (patch_shellcode(tgt->hdr, hdr->ramdisk_addr) < 0) {
		printf("[-] Failed to patch shellcode.\n");
		return 1;
	}

	/* Ramdisk must be aligned to a page boundary */
	hdr->kernel_size = ((hdr->kernel_size + page_mask) & ~page_mask) + hdr->ramdisk_size;

	/* Guarantee 16-byte alignment */
	offset = tgt->check_sigs & 0xf;

	hdr->ramdisk_addr = tgt->check_sigs - offset;

	if (tgt->lg) {
		fake_size = page_size;
		hdr->ramdisk_size = page_size;
	}
	else {
		fake_size = 0x200;
		hdr->ramdisk_size = 0;
	}

	/* Write the image header */
	if (write(ofd, orig, page_size) != page_size) {
		printf("[-] Failed to write header to output file.\n");
		return 1;
	}

	page_kernel_size = (orig_kernel_size + page_mask) & ~page_mask;

	/* Write the kernel */
	if (write(ofd, orig + page_size, page_kernel_size) != page_kernel_size) {
		printf("[-] Failed to write kernel to output file.\n");
		return 1;
	}

	page_ramdisk_size = (orig_ramdisk_size + page_mask) & ~page_mask;

	/* Write the ramdisk */
	if (write(ofd, orig + page_size + page_kernel_size, page_ramdisk_size) != page_ramdisk_size) {
		printf("[-] Failed to write ramdisk to output file.\n");
		return 1;
	}

	/* Write fake_size bytes of original code to the output */
	buf = malloc(fake_size);
	if (!buf) {
		printf("[-] Out of memory.\n");
		return 1;
	}

	lseek(aboot_fd, tgt->check_sigs - aboot_base - offset, SEEK_SET);
	read(aboot_fd, buf, fake_size);

	if (write(ofd, buf, fake_size) != fake_size) {
		printf("[-] Failed to write original aboot code to output file.\n");
		return 1;
	}

	/* Save this position for later */
	pos = lseek(ofd, 0, SEEK_CUR);

	/* Write the device tree if needed */
	if (hdr->dt_size) {

		printf("[+] Writing device tree.\n");

		if (write(ofd, orig + page_size + page_kernel_size + page_ramdisk_size, hdr->dt_size) != hdr->dt_size) {
			printf("[-] Failed to write device tree to output file.\n");
			return 1;
		}
	}

	lseek(ofd, pos - (fake_size - offset), SEEK_SET);

	/* Write the patch */
	if (write(ofd, patch, sizeof(patch)) != sizeof(patch)) {
		printf("[-] Failed to write patch to output file.\n");
		return 1;
	}

	close(ifd);
	close(ofd);
	close(aboot_fd);

	printf("[+] Output file written to %s\n", argv[4]);

	return 0;
}
