/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

/* Show statistics from kstats */

#include "ustats.h"

int main(int ac, char **av)
{
	return (ac == 1) ? 0 : ustats_cmd(av[1], ac > 2 ? av[2] : NULL);
}
