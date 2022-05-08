/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file argon.h
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @version 0.1
 * @date 2022-05-08
 * 
 * @copyright Copyright (c) Stefano Moioli 2022
 */
#ifndef __ARGON_H
#define __ARGON_H

#define HAS_FLAG(x, f) (( (x) & f) == f)
enum argon_reset_flags {
	ARGON_RESET_FULL = 1 << 0,
	ARGON_KEEP_BUFFER = 1 << 1,
	ARGON_SKIP_GC = 1 << 2,
	ARGON_FAST_INIT = 1 << 3,
	ARGON_SKIP_INIT = 1 << 4
};

enum argon_gc_pool {
	ARGON_POOL_INIT = 1 << 0,
	ARGON_POOL_LIVE = 1 << 1
};

#endif