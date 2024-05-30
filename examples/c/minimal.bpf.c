// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/*
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	// unsigned const size = 2048;
	static __u8 arr[1112048] = {1, 2, };

	if (pid != my_pid)
		return 0;
	unsigned int i;
	// for (i = 0; i < sizeof(arr); i++) {
	// 	arr[i] = i % 200;
	// }

	// memset(arr, 2, sizeof(arr));

	unsigned x = 0;
	if (pid > 116500) {
		x = 0;
	} else {
		x = 1024;
	}
	bpf_printk("BPF triggered from PID %d and val %d.\n", pid, arr[x]);

	return 0;
}
*/

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}