/*
 * Broadcom Host Remote Download Utility
 *
 * Copyright (C) 2014, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: bcmdl.c 473475 2014-04-29 07:39:59Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <trxhdr.h>
#include "usbrdl.h"
#include "usb_osl.h"
#include <sys/time.h>
#include <bcmdevs.h>
#include <bcmutils.h>
#include <bcmendian.h>

#define DECOMP_SIZE_MAX		(2 * 1024 * 1024)
#define UNCMP_LEN_MAX		0x70000 /* 0x5d000 -> to support 43236 fulldongle */

/* #define BCMQT */

#define USB_SFLASH_DLIMAGE_WAIT		1    /* SFlash wait interval (s) */
#define USB_SFLASH_DLIMAGE_LIMIT	60   /* SFlash wait limit (s) */

/* bitmask for error injection */
#define ERR_INJ_TRX_CHKS		0x01
#define ERR_INJ_TRX_MAGIC		0x02
#define ERR_INJ_IMG_TOO_BIG		0x04
#define ERR_INJ_NVRAM_TOO_BIG	0x08

static struct bcm_device_id bcm_device_ids[] = {
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43341},
	{"brcm RDL (alpha)", BCM_DNGL_VID, 0xcafe },
	{"brcm RDL", BCM_DNGL_VID, 0xbd11},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4328},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4322},
	{"brcm RDL", BCM_DNGL_VID, 0xbd14},
	{"brcm RDL", BCM_DNGL_VID, 0xbd15},
	{"brcm RDL", BCM_DNGL_VID, 0x4319},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4319},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43236},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4332},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4330},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4324},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43242},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43143},
	{"brcm RDL", 0x0846, 0x9011},	/* Netgear WNDA3100V2 */
	{"brcm RDL", 0x050D, 0xD321},	/* Dynex */
	{"brcm RDL", 0x0720, BCM_DNGL_BL_PID_4328},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4335},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4345},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4360},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_4350},
	{"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43909},
        {"brcm RDL", BCM_DNGL_VID, BCM_DNGL_BL_PID_43569},
	{NULL, 0xffff, 0xffff}
};

static char *progname;
static int check_file(unsigned char *headers);

static int verbose;

static void
print_nvram_vars(char *varbuf)
{
	char *p1 = varbuf; /* points at start of word */
	char *p2 = p1;

	printf("NVRAM variables:\n");
	while (p1 != p2 || p1[0] != 0) {
		p2++;
		if (*p2 == 0) {
			printf("%s\n", p1);
			p2++;
			p1 = p2;
		}
	}
}

static int
WriteFile(char *outfile, void *buffer, uint count)
{
	int fd;
	ssize_t status = -1;

	if ((fd = open(outfile, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)) >= 0) {
		status = write(fd, buffer, count);
		if (status <= 0)
			printf("Unable to write %s: %s\n", outfile, strerror(errno));
		else
			printf("Wrote %u bytes to %s\n", (uint)status, outfile);
		close(fd);
	} else {
		printf("Unable to open %s: %s\n", outfile, strerror(errno));
	}

	return status;
}

static int
ReadFiles(char *fwfile, char *nvfile, unsigned char **buffer, int err_inj)
{
	int fd;
	struct stat filest;
	int len, fwlen, actual_len, nvlen = 0;
	unsigned long status;
	unsigned char *buf = NULL;
	int ret = 0;
	int i = 0;
	struct trx_header *hdr;

	if (stat(fwfile, &filest)) {
		printf("bcmdl: %s: %s\n", fwfile, strerror(errno));
		return -1;
	}
	len = fwlen = filest.st_size;

	if (nvfile) {
		if (stat(nvfile, &filest)) {
			printf("bcmdl: %s: %s\n", nvfile, strerror(errno));
			return -1;
		}
		nvlen = filest.st_size;
		len += nvlen;
	}
	if ((buf = malloc(len + 4)) == NULL) {
		printf("Unable to allocate %d bytes!\n", len);
		return -ENOMEM;
	}

	hdr = (struct trx_header *)buf;

	/* Open the firmware file */
	if ((fd = open(fwfile, O_RDONLY)) < 0) {
		printf("Unable to open %s!\n", fwfile);
		ret = -errno;
		goto error;
	}

	/* Read the firmware file into the buffer */
	status = read(fd, buf, fwlen);

	/* Close the firmware file */
	close(fd);

	if (status < fwlen) {
		printf("Short read in %s!\n", fwfile);
		ret = -EINVAL;
		goto error;
	}

	/* Validate the format/length etc of the file */
	if ((actual_len = check_file(buf)) <= 0) {
		printf("bcmdl:  Failed input file check\n");
		ret = -1;
		goto error;
	}

	if (nvfile) {
		unsigned int pad;

		/* if fw is already signed & user wants to append nvram don't allow */
		if (ISTRX_V2(hdr)) {
			if (hdr->offsets[TRX_OFFSETS_DSG_LEN_IDX]) {
				printf("Can't append nvram to already signed image!\n");
				ret = -errno;
				goto error;
			}
		}

		/* Open the nvram file */
		if ((fd = open(nvfile, O_RDONLY)) < 0) {
			printf("Unable to open %s!\n", nvfile);
			ret = -errno;
			goto error;
		}

		/* Read the nvram file into the buffer */
		status = read(fd, buf + actual_len, nvlen);

		/* Close the nvram file */
		close(fd);

		if (status < nvlen) {
			printf("Short read in %s!\n", nvfile);
			ret = -EINVAL;
			goto error;
		}
		/* process nvram vars if user specified a text file instead of binary */
		nvlen = process_nvram_vars((char *)&buf[actual_len], (unsigned int)nvlen);
		if (nvlen % 4) {
			pad = 4 - (nvlen % 4);
			for (i = 0; i < pad; i++)
				buf[actual_len + nvlen + i] = 0;
			nvlen += pad;
		}

		if (verbose)
			print_nvram_vars((char *)&buf[actual_len]);

		/* Pass the actual fw len */
		hdr->offsets[TRX_OFFSETS_NVM_LEN_IDX] = htol32(nvlen);
	} else
		nvlen = ltoh32(hdr->offsets[TRX_OFFSETS_NVM_LEN_IDX]);

	/* If fw is TRXV2 signed & take sign & cfg field length to consideration. */
	if (ISTRX_V2(hdr)) {
		actual_len += ltoh32(hdr->offsets[TRX_OFFSETS_DSG_LEN_IDX]) +
			ltoh32(hdr->offsets[TRX_OFFSETS_CFG_LEN_IDX]);
	}

	/* fix up len to be actual len + nvram len */
	len = actual_len + nvlen;
	/* update trx header with added nvram bytes */
	hdr->len = htol32(len);
	/* Calculate CRC over header */
	hdr->crc32 = hndcrc32((uint8 *)&hdr->flag_version,
		SIZEOF_TRX(hdr) - OFFSETOF(struct trx_header, flag_version),
		CRC32_INIT_VALUE);

	/* Calculate CRC over data */
	for (i = SIZEOF_TRX(hdr); i < len; ++i)
		hdr->crc32 = hndcrc32((uint8 *)&buf[i], 1, hdr->crc32);

	hdr->crc32 = htol32(hdr->crc32);

	if (err_inj & ERR_INJ_NVRAM_TOO_BIG)
		hdr->offsets[TRX_OFFSETS_NVM_LEN_IDX] = 0x10000000;

	if (err_inj & ERR_INJ_TRX_CHKS)
		hdr->crc32 -= 1;

	if (err_inj & ERR_INJ_TRX_MAGIC)
		hdr->magic = 0;

	if (err_inj & ERR_INJ_IMG_TOO_BIG)
		hdr->offsets[TRX_OFFSETS_DLFWLEN_IDX] = 0x10000000;

	*buffer = buf;
	return len;

error:
	if (buf)
		free(buf);
	return ret;
}

static void
usage(void)
{
	printf("Usage: %s [options] <filename>\n", progname);
	printf("utility that downloads a firmware image into an USB dongle.\n");
	printf("does not require a wl driver.\n");
	printf("options:\n");
	printf("   -c			On error, retry forever\n");
	printf("   -r			Issue reboot command to device\n");
	printf("   -t			Issue device reset command \n");
	printf("   -n <nvram file>	Specify nvram download file (binary/text format)\n");
	printf("   -w <output file>	Write image file instead of downloading\n");
	printf("   -i <pid>		Specify pid. 0xFFFF will list all devices\n");
	printf("   -v			Verbose. Print nvram variables.\n");
	printf("   Error injection options (to verify bootloader):\n");
	printf("   -ic			Force corrupt crc32 on trx header\n");
	printf("   -im			Force corrupt magic on trx header\n");
	printf("   -ib			Force image size too big in trx header\n");
	printf("   -in			Force nvram size too big on trx header\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	unsigned char *dlfile = NULL, *dlpos = NULL;
	char *fwfn = NULL;
	char *nvfn = NULL;
	char *outfn = NULL;
	uint pid;
	int dllen;
	unsigned int sent = 0;
	int send, status;
	rdl_state_t rdl;
	bootrom_id_t id;
	int started = 0, cont = 0, reboot = 0, reset = 0, dl_go = 1, err_inj = 0;
	struct bcm_device_id *bcmdev;
	struct usbinfo *info = NULL;
	double t1, t2, elapsed;
	struct timeval tp;
	unsigned int gpout = 0x0, gpen = 0xffff;
	int first_time = 1;
	uint16 wait, wait_time;

	progname = argv[0];

	if ((argc < 2) || (argc > 13)) {
		usage();
	}

	/* Skip program name */
	--argc;
	++argv;

	for (; *argv; argv++) {
		if (strcmp(*argv, "-c") == 0) {
			cont = 1;
		} else if (strcmp(*argv, "-ic") == 0) {
			err_inj |= ERR_INJ_TRX_CHKS;
		} else if (strcmp(*argv, "-im") == 0) {
			err_inj |= ERR_INJ_TRX_MAGIC;
		} else if (strcmp(*argv, "-ib") == 0) {
			err_inj |= ERR_INJ_IMG_TOO_BIG;
		} else if (strcmp(*argv, "-in") == 0) {
			err_inj |= ERR_INJ_NVRAM_TOO_BIG;
		} else if (strcmp(*argv, "-r") == 0) {
			reboot = 1;
		} else if (strcmp(*argv, "-s") == 0) {
			dl_go = 0;
		} else if (strcmp(*argv, "-t") == 0) {
			reset = 1;
		} else if (strcmp(*argv, "-v") == 0) {
			verbose = 1;
		} else if (strcmp(*argv, "-n") == 0) {
			if (!*++argv) {
				printf("-n: missing argument\n");
				usage();
			}
			nvfn = *argv;
		} else if (strcmp(*argv, "-w") == 0) {
			if (!*++argv) {
				printf("-w: missing argument\n");
				usage();
			}
			outfn = *argv;
		} else if (strcmp(*argv, "-i") == 0) {
			if (!*++argv) {
				printf("-i: missing argument\n");
				usage();
			}

			errno = 0;
			pid = strtol(*argv, NULL, 0);
			if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
				(errno != 0 && pid == 0)) {
				perror("strtol");
				exit(EXIT_FAILURE);
			}

			if (pid) {
				struct bcm_device_id *identry;

				identry = &bcm_device_ids[0];
				identry->prod = pid;

				bcm_device_ids[1].name = NULL;

				printf("user-specified pid 0x%x\n", identry->prod);
			}
		} else
			fwfn = *argv;
	} /* for */

	/* Only download the image if the file write option (-w) is not used */
	if (outfn == NULL) {

		bzero(&rdl, sizeof(rdl_state_t));

		info = usbdev_init(bcm_device_ids, &bcmdev);
		if ((info == NULL) || (bcmdev == NULL)) {
			printf("Error: usbdev_init failed...\n");
			return -1;
		}

		printf("Found device: vend=0x%x prod=0x%x\n", bcmdev->vend, bcmdev->prod);

		if (bcmdev->vend == 0x0a5c && bcmdev->prod == 0x4319) {
			sleep(1);
			status = usbdev_control_write(info, 0xff, 0x0064, 0x1800, (char*)&gpout,
			      4, FALSE, TIMEOUT);
			status = usbdev_control_write(info, 0xff, 0x0068, 0x1800, (char*)&gpen,
			      4, FALSE, TIMEOUT);
			usbdev_deinit(info);
			return 0;

		}
		if (reset) {
			status = usbdev_reset(info);
			if (status < 0)
				printf("error %d issuing reset command\n", status);
			else
				printf("device has been reset\n");
			goto done;
		}

		if (reboot) {
			status = usbdev_control_read(info, DL_REBOOT, 1, 0, (char*)&rdl,
						     sizeof(rdl_state_t), TRUE, TIMEOUT);
			if (status < 0)
				printf("error %d issuing reboot command\n", status);
			else
				printf("success issuing reboot command\n");

			goto done;
		}
	}

	dllen = ReadFiles(fwfn, nvfn, &dlfile, err_inj);
	if (dllen <= 0)
		goto err;

	printf("File Length: %d\n", dllen);

	if (outfn != NULL) {
		WriteFile(outfn, dlfile, dllen);
		goto done;
	}

	if (bcmdev->prod != 0xcafe) {
		bzero(&id, sizeof(id));
		status = usbdev_control_read(info, DL_GETVER, 1, 0, (char*)&id,
		     sizeof(bootrom_id_t), TRUE, TIMEOUT);

		if (status < 0)
			goto err;

		id.chip = ltoh32(id.chip);
		id.chiprev = ltoh32(id.chiprev);
		id.ramsize = ltoh32(id.ramsize);
		id.remapbase = ltoh32(id.remapbase);
		id.boardtype = ltoh32(id.boardtype);
		id.boardrev = ltoh32(id.boardrev);

		printf("ID : Chip 0x%x Rev 0x%x", id.chip, id.chiprev);

		if (id.ramsize != 0 || id.remapbase != 0 ||
		    id.boardtype != 0 || id.boardrev != 0) {
			printf("RamSize %d RemapBase 0x%08x BoardType %d BoardRev %d",
				id.ramsize, id.remapbase, id.boardtype, id.boardrev);
		}
		printf("\n");
	}

start:
	/* Limit the amount of times we attempt to start */
	started++;
	if (!cont && (started > 5))
		goto err;

	if (cont) {
		printf("\r%d", started);
		fflush(stdout);
	} else
		printf("start\n");

	sent = 0;
	dlpos = dlfile;

	status = usbdev_control_read(info, DL_START, 1, 0, (char*)&rdl,
	     sizeof(rdl_state_t), TRUE, TIMEOUT);
	if (status < 0)
		goto err;

	rdl.state = ltoh32(rdl.state);
	rdl.bytes = ltoh32(rdl.bytes);

	if (rdl.state != DL_WAITING)
		goto start;

	gettimeofday(&tp, NULL);
	t1 = (double)tp.tv_sec + (1.e-6) * tp.tv_usec;

	/* Load the image */
	while ((rdl.bytes != dllen) && (status >= 0)) {
		/* Wait until the usb device reports it received all the bytes we sent */
		if ((rdl.bytes == sent) && (rdl.bytes != dllen)) {

			if ((dllen-sent) < RDL_CHUNK)
				send = dllen-sent;
			else
				send = RDL_CHUNK;

			/* linux libusb api does not issue ZLPs correctly */
			/* ensure we are not an even multiple of 64 for usb 1.1 */
			/* which also covers the usb2.0 case (512) */
			if (!(send % 64))
				send -= 4;

			status = usbdev_bulk_write(info, dlpos, send, TIMEOUT);
			if (status < 0) {
				printf("bulk write failed w/status %d\n", status);
				goto err;
			}

			dlpos += send;
			sent += send;
			if (first_time) {
				status = usbdev_control_read(info, DL_GETSTATE, 1, 0,
					(char*)&rdl, sizeof(rdl_state_t), TRUE, TIMEOUT);
				if (status < 0)
					goto err;

				rdl.state = ltoh32(rdl.state);
				rdl.bytes = ltoh32(rdl.bytes);

				/* exit if specified download data is too large */
				if (rdl.state == DL_IMAGE_TOOBIG) {
					printf("ERROR : %d\n", rdl.state);
					goto done;
				}
				first_time = 0;
			}
		}

		/* 43236a0 bootloader runs from sflash, which is slower than rom
		 * Wait for downloaded image crc check to complete in the dongle
		 */
		wait = 0;
		wait_time = USB_SFLASH_DLIMAGE_WAIT;
		while (usbdev_control_read(info, DL_GETSTATE, 1, 0, (char*)&rdl,
			sizeof(rdl_state_t), TRUE, TIMEOUT) < 0) {
			if ((id.chip == 43236) && (id.chiprev == 0)) {
				printf("43236a0 SFlash delay, waiting for dongle crc check "
					"to complete!!!\n");
				sleep(wait_time);
				wait += wait_time;
				if (wait >= USB_SFLASH_DLIMAGE_LIMIT)
					goto err;
			}
			else
				goto err;
		}

		rdl.state = ltoh32(rdl.state);
		rdl.bytes = ltoh32(rdl.bytes);

		/* restart if a potential bit error is reported */
		if ((rdl.state == DL_BAD_HDR) || (rdl.state == DL_BAD_CRC)) {
			printf("ERROR : %d\n", rdl.state);
			goto start;
		}

		/* exit if specified download data is too large */
		if (rdl.state == DL_NVRAM_TOOBIG) {
			printf("ERROR : %d\n", rdl.state);
			goto done;
		}
	}

	gettimeofday(&tp, NULL);
	t2 = (double)tp.tv_sec + (1.e-6) * tp.tv_usec;
	elapsed = t2 - t1;

	/* Check we are runnable */
	status = usbdev_control_read(info, DL_GETSTATE, 1, 0, (char*)&rdl,
	                             sizeof(rdl_state_t), TRUE, TIMEOUT);

	if (status < 0)
		goto err;

	rdl.state = ltoh32(rdl.state);
	rdl.bytes = ltoh32(rdl.bytes);

	if (!cont)
		printf("rdl.state 0x%x\n", rdl.state);

	/* Repeat forever */
	if (cont)
		goto start;

	/* Start the image */
	if (rdl.state == DL_RUNNABLE && dl_go) {
		status = usbdev_control_read(info, DL_GO,
		                             1, 0, (char*)&rdl,
		                             sizeof(rdl_state_t),
		                             TRUE, TIMEOUT);
	} else if (dl_go) {
		/* try again */
		goto start;
	}

	printf("elapsed download time %f\n", elapsed);

	if (status < 0)
		goto err;

done:
	if (info != NULL)
		usbdev_deinit(info);

	free(dlfile);

	return 0;

err:
	/* We could issue a DL_REBOOT here */
	if (dlfile)
		free(dlfile);
	printf("Error: rdl state %d bytes 0x%x, start count %d\n", rdl.state, rdl.bytes, started);
	return -1;
}

/*
 * checks the file headers and the gzip image crc and length
 *
 * returns non zero on error
 */

#define Z_DEFLATED   8
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */
#define GZIP_TRL_LEN 8    /* 8 bytes, |crc|len| */

static int
check_file(unsigned char *headers)
{
	int method, flags, len, status;
	unsigned int uncmp_len, uncmp_crc, dec_crc, crc_init;
	struct trx_header *trx;
	unsigned char *file = NULL;
	unsigned char gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */
	z_stream d_stream;
	unsigned char unused;
	int actual_len = -1;

	/* Extract trx header */
	trx = (struct trx_header *)headers;
	if (ltoh32(trx->magic) != TRX_MAGIC) {
		printf("Error: trx bad hdr %x\n", ltoh32(trx->magic));
		goto err;
	}

	headers += SIZEOF_TRX(trx);

	if (ltoh32(trx->flag_version) & TRX_UNCOMP_IMAGE) {
		actual_len = ltoh32(trx->offsets[TRX_OFFSETS_DLFWLEN_IDX]) +
		                     SIZEOF_TRX(trx);
		return actual_len;
	} else {
		/* Extract the gzip header info */
		if ((*headers++ != gz_magic[0]) || (*headers++ != gz_magic[1])) {
			printf("Error: gzip bad hdr\n");
			goto err;
		}

		method = (int) *headers++;
		flags = (int) *headers++;

		if (method != Z_DEFLATED || (flags & RESERVED) != 0) {
			printf("Error: gzip bad hdr\n");
			goto err;
		}
	}

	/* Discard time, xflags and OS code: */
	for (len = 0; len < 6; len++)
		unused = *headers++;

	if ((flags & EXTRA_FIELD) != 0) { /* skip the extra field */
		len = (uint32) *headers++;
		len += ((uint32)*headers++)<<8;
		/* len is garbage if EOF but the loop below will quit anyway */
		while (len-- != 0) unused = *headers++;
	}

	if ((flags & ORIG_NAME) != 0) { /* skip the original file name */
		while (*headers++ && (*headers != 0));
	}

	if ((flags & COMMENT) != 0) {   /* skip the .gz file comment */
		while (*headers++ && (*headers != 0));
	}

	if ((flags & HEAD_CRC) != 0) {  /* skip the header crc */
		for (len = 0; len < 2; len++) unused = *headers++;
	}

	headers++;

	/* Inflate the code */

	/* create space for the uncompressed file */
	if (!(file = malloc(DECOMP_SIZE_MAX))) {
		printf("check_file : failed malloc\n");
		goto err;
	}

	/* Initialise the decompression struct */
	d_stream.next_in = NULL;
	d_stream.avail_in = 0;
	d_stream.next_out = NULL;
	d_stream.avail_out = DECOMP_SIZE_MAX;
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	if (inflateInit2(&d_stream, -15) != Z_OK) {
		printf("Err: inflateInit2\n");
		goto err;
	}

	d_stream.next_in = headers;
	d_stream.avail_in = ltoh32(trx->len);
	d_stream.next_out = (unsigned char*)file;

	status = inflate(&d_stream, Z_SYNC_FLUSH);

	if (status != Z_STREAM_END)	{
		printf("Error: decompression failed\n");
		goto err;
	}

	uncmp_crc = *d_stream.next_in++;
	uncmp_crc |= *d_stream.next_in++<<8;
	uncmp_crc |= *d_stream.next_in++<<16;
	uncmp_crc |= *d_stream.next_in++<<24;

	uncmp_len = *d_stream.next_in++;
	uncmp_len |= *d_stream.next_in++<<8;
	uncmp_len |= *d_stream.next_in++<<16;
	uncmp_len |= *d_stream.next_in++<<24;

	actual_len = (int) (d_stream.next_in - (unsigned char *)trx);

	/* check file length will fit: as of Oct 27th 2004 the data segment
	 * of the download code is set at 0x5d000, so only this much code can
	 * be downloaded
	 */
	if (uncmp_len > UNCMP_LEN_MAX &&
	    trx->offsets[TRX_OFFSETS_DLFWLEN_IDX] != 0x80300000) {
		printf("decompression: file length too large 0x%x\n", uncmp_len);
		goto err;
	}

	/* Do a CRC32 on the uncompressed data */
	crc_init = crc32(0L, Z_NULL, 0);
	dec_crc = crc32(crc_init, file, uncmp_len);

	if (dec_crc != uncmp_crc) {
		printf("decompression: bad crc check (file len %d)\n", uncmp_len);
		goto err;
	}

	BCM_REFERENCE(unused);

	free(file);

	return actual_len;

err:
	if (file)
		free(file);
	return -1;
}
