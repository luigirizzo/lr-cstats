#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Google LLC.
#
# shell processing for ustats output

[[ "$#" -gt 0 ]] && srcfile="$1"
cat ${srcfile} | od -Ad -t u8 -w16 -j2048 -v | awk '
BEGIN { kstats = 2048; t0_start = 4096 + 64; slot=0; prev_tid = -1; }
$1 == kstats {frac_bits = $2; entry_size = $3; }
$1 == kstats + 16 { n_slots = $2; entries = $3 }
$1 == kstats + 32 { active = $2;
    printf("bits %d entries %d slots %d entry_size %d\n",
	frac_bits, entries, n_slots, entry_size);
}

$1 >= t0_start {
  tid = int(($1 - t0_start) / entry_size);
  slot = (tid == prev_tid) ? slot + 1 : 0;
  prev_tid = tid;
  if (slot >= n_slots || $2 == 0) next;
  h_samples[tid][slot] = int($2);
  h_sum[tid][slot] = int($3);
}

END {
  for (tid = 0; tid < entries; tid++) {
    for (slot = 0; slot < n_slots; slot++) totals[tid] += h_samples[tid][slot];
    grand_total += totals[tid];
  }
  SUM_SCALE=20
  for (slot = 0; slot < n_slots; slot++) {
    samples = 0; sum = 0; samples_cumulative = 0;
    bucket = rshift(slot, frac_bits)
    sum_shift = bucket < SUM_SCALE ? 0 : bucket - SUM_SCALE;
    for (tid = 0; tid < entries; tid++) {
      d = h_sum[tid][slot];
      n = h_samples[tid][slot];
      sum += d;
      samples += n;
      partials[tid] += n;
      samples_cumulative += partials[tid];
      if (n == 0) continue;
      avg = lshift(int(d / n), sum_shift);
      printf("slot %4d TD  %-4d count %8lu avg %8lu p %8.6f\n",
	slot, tid, n, avg, partials[tid] / totals[tid]);
    }
    if (samples == 0) continue;
    avg = lshift(int(sum / samples), sum_shift);
    printf("slot %4d TDS %-4d count %8lu avg %8lu p %8.6f\n",
	slot, entries, samples, avg, samples_cumulative / grand_total);
  }
}
'
