// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <linux/fpga-dfl.h>

#include "../../kselftest_harness.h"

TEST(afu_intr)
{
	struct dfl_fpga_port_info port_info;
	uint32_t irq_num = UINT32_MAX;
	int devfd, status;

	devfd = open("/dev/dfl-port.0", O_RDONLY);
	if (devfd < 0)
		SKIP(0, "no fpga afu device 0");
	/*
	 * From fpga-dl.h :
	 * Currently hardware supports up to 1 irq.
	 * Return: 0 on success, -errno on failure.
	 */
	status = ioctl(devfd, DFL_FPGA_PORT_ERR_GET_IRQ_NUM, &irq_num);
	ASSERT_EQ(0, status) {
		TH_LOG("ioctl() failed to get the number irqs");
	}
	ASSERT_LT(irq_num, 256) {
		TH_LOG("unexpeced number of irqs");
	}
	close(devfd);
}

TEST_HARNESS_MAIN
