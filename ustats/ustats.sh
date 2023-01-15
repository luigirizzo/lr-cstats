#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021-2023 Google LLC.
# shell processing for ustats output, max 2KB
src=$0
[[ "$#" -gt 0 ]] && src="$1"
od -Ad -t u1 -w16 -j2048 -v ${src} | awk '
function m(a0, a1, a2, a3, a4) { return int(a0)+256*(a1+256*(a2+256*(a3))); }
BEGIN { kstats = 2048; t0_start = 4096; slot=0; prev_tid = -1; }
$1 == kstats {frac_bits = m($2,$3,$4,$5); entry_size = m($10,$11,$12,$13); }
$1 == kstats + 16 { n_slots = m($2,$3,$4,$5); tables = m($10,$11,$12,$13) }
$1 == kstats + 32 { active = m($2,$3,$4,$5);
    h_name[tables] = "TOTALS";
    printf("# bits %d tables %d slots %d entry_size %d\n",
	frac_bits, tables, n_slots, entry_size);
}

$1 >= t0_start  {
  tid = int(($1 - t0_start) / entry_size);
  ofs = ($1 - t0_start) % entry_size;
  if (ofs < 64) {
    if (ofs == 32) {s=""; for (i=2;$i>0;i++) s = s sprintf("%c", $i); h_name[tid] = s;}
    next;
  }
  slot = (tid == prev_tid) ? slot + 1 : 0;
  prev_tid = tid;
  cnt = m($2, $3, $4, $5) + 0x10000000*m($6, $7, $8, $9)
  sum = m($10,$11,$12,$13) + 0x10000000*m($14, $15, $16, $17)
  if (slot >= n_slots || cnt == 0) next;
  i = "" tid "_" slot # awk 3.1.5 does not have multi index
  h_cnt[i] = cnt
  h_sum[i] = sum
  h_tot[tid] += cnt
  j = "" tables "_" slot
  h_cnt[j] += cnt
  h_sum[j] += sum
  h_tot[tables] += cnt
}

END {
  SUM_SCALE=20
  for (tid = 0; tid <= tables; tid++) {
    printf("# TABLE %3d : \"%s\" samples %lu\n", tid, h_name[tid], h_tot[tid]);
    tot = 0;
    for (slot = 0; slot < n_slots; slot++) {
      bucket = rshift(slot, frac_bits)
      sum_shift = bucket < SUM_SCALE ? 0 : bucket - SUM_SCALE;
      i = "" tid "_" slot
      n = h_cnt[i];
      if (n == 0) continue;
      d = h_sum[i];
      tot += n;
      avg = lshift(int(d / n), sum_shift);
      printf("slot %4d TABLE%s %-4d count %8lu avg %8lu p %8.6f\n",
	slot, (tid == tables ? "S" : " "), tid, n, avg, tot / h_tot[tid]);
    }
  }
}
'
exit 0
