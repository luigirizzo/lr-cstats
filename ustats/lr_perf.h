/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

#ifndef _LR_PERF_H
#define _LR_PERF_H

/* Docs and helpers for perf counters

Note: we can read much in the same way performance counters.

https://software.intel.com/sites/default/files/m/5/2/c/f/1/30320-Nehalem-PMU-Programming-Guide-Core.pdf
https://software.intel.com/sites/default/files/managed/8b/6e/335279_performance_monitoring_events_guide.pdf

sudo modprobe msr
echo 2 | sudo tee /sys/devices/cpu/rdpmc    # enable RDPMC always
sudo rdmsr -a 0x38F # should read 70000000f # IA32_PERF_GLOBAL_CTRL
# high3 are fixed counters, low 4 are programmable counters
sudo rdmsr -a 0x38D

rdpmc CX value (other cause segfault):
	0x40000000	instructions retired
	0x40000001	unhalted cycles
	0x40000002	unhalted REF cycles 
	0		ctr0
	1		ctr1
	2		ctr2
	3		ctr3

*/

//	Registers			MSR value RDPMC
#define	IA32_PMC0			0xC1	// 0
#define	IA32_PMC1			0xC2	// 1
#define	IA32_PMC2			0xC3	// 2
#define	IA32_PMC3			0xC4	// 3

/* Function selection for programmable event counter */
// b7-b0 EvtSel	event logic, machine specific
// b15-8 EvtMsk	condition qualifier
#define	EvtBranch		0x00c4
#define	EvtBranchMisses		0x00c5
#define EvtCpuCycles		0x003c // C0 clocks, variable freq
#define EvtBusCycles		0x013c	// C0 clocks, fixed freq 100MHz?
#define EvtInstructions		0x00c0	// Instructions retired
#define EvtBranches		0x00c4	// Branch Inst. retired
#define EvtBranchMisses		0x00c5	// Branch Miss Inst. retired
#define EvtLLCReference		0x4f2e
#define EvtLLCMiss		0x412e	
#define EvtRefCycles		0x0300	// XXX not working?
#define EvtL2Misses		0x3f24	// any L2 miss

// b16	 USR	count on privilege level 1,2,3
// b17	 OS	count on privilege level 0
// b18	 E	enable on asserted to deasserted
// b20   INT	intr on overflow
// b21	 AnyThr	count on any thread on this core
// b22   EN	local enable
// b23	 INV	invert condition
// b24   CMASK	increment counter if evcount >= CMASK, CMASK>0
// other bits are for comparing
#define	PerfEvtSel0			0x186
#define	PerfEvtSel1			0x187
#define	PerfEvtSel2			0x188
#define	PerfEvtSel3			0x189
#define	IA32_MISC_ENABLE		0x1A0
	// bit7	per-core monitoring available
	// bit12	PEBS available
#define	OFFCORE_RSP_0			0x1A6
#define	OFFCORE_RSP_1			0x1A7
#define	LBR_SELECT			0x1C8
#define	MSR_LASTBRANCH_TOS		0x1C9
#define	IA32_DEBUGCTL			0x1D9
	// tracing, single stepping and LastBrancRecord
#define	PERF_FIXED_CTR0			0x309	// 0x40000000
	// Inst_Retired.ANY, same as 0x00c0

#define	PERF_FIXED_CTR1			0x30A	// 0x40000001
	// CPU_CLK_UNHALTED, same as 003c

#define	PERF_FIXED_CTR2			0x30B	// 0x40000002
	// CPU_CLK_UNHALTED_REF_TSC similar to 0x13c but at TSC rate

#define	IA32_PERF_CAPABILITIES		0x345
	// PEBs etc
#define	IA32_FIXED_CTR_CTRL		0X38D
	// control fixed counters b3-0 FC0, b7-4 FC1 b11-8 FC2
	// b0 OS count on PL0
	// b1 USR count on PL 123 (swapped wrt PerfEvtSel*)
	// b2 AnyThr count on AnyThread on this core
	// b3 INT enable interrupt on overflow
	// FC1: b7-4, FC2: b11-8
#define	IA32_PERF_GLOBAL_STATUS		0x38E
	// b3-b0	ro overflow programmable counter
	// b34-b32	ro overflow fixed counter
	// b63-b61	perfmon, pebs, uncore threshold
#define	IA32_PERF_GLOBAL_CTRL		0x38F
	// b3-b0	global enable programmable counter
	// b34-b32	global enable fixed counter
#define	IA32_PERF_GLOBAL_OVF_CTRL	0x390
	// write only, clear bits in IA32_PERF_GLOBAL_STATUS
#define	IA32_PEBS_ENABLE		0x3F1
#define	PEBS_LD_LAT_THRESHOLD		0x3F6
#define	IA32_DS_AREA			0x600
#define	MSR_LASTBRANCH_x_FROM_IP 0x680	// (0 <= x <= 15) 0x680-0x68F
#define	MSR_LASTBRANCH_x_TO_IP 0x6c0	// (0 <= x <= 15) 0x6C0–0x6CF

/* Enable user rdpmc with
 * echo 2 > /sys/bus/event_source/devices/cpu/rdpmc 
 */
#ifdef __x86_64__
static inline uint64_t rdpmc_now(int reg)
{
	uint32_t low, high;
	asm volatile("rdpmc": "=a" (low), "=d" (high): "c" (reg));
	return low | ((uint64_t)(high) << 32);
}
#endif

#endif /* _LR_PERF_H */
