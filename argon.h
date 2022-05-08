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

enum argon_reset_flags {
	ARGON_RESET_FULL = 0,
	ARGON_KEEP_BUFFER = 1 << 0
};

#endif