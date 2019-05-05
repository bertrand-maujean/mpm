/*
    MPM 'Master Password Manager' 
	Cryptographically secure Secret Sharing to store residual secret.
    Copyright (C) 2018-2019 Bertrand MAUJEAN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    A copy of the GNU GPLv3 License is included in the LICENSE.txt file
    You can also see <https://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdarg.h>
#include "debug_file.h"

#ifdef DEBUG
int debug_level = 0;
FILE *debug_file = NULL;
#endif


void debug_printf(int level, const char *format, ...) {
	#ifdef DEBUG
    va_list ap;
    va_start(ap, format);
    if (debug_file != NULL) {
            if (debug_level >= level) {
                    vfprintf(debug_file, format, ap);
                    fflush(debug_file);
            }
    }
    va_end(ap);
	#endif
}

void debug_init(const char *filename, int level) {
	#ifdef DEBUG
	debug_file = fopen(filename, "at");
	debug_level = level;
	#endif
}

void debug_deinit() {
	#ifdef DEBUG
	if (debug_file) fclose(debug_file);
	#endif
}
