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


#ifndef HAVE_DEBUG_FILE_H
#define HAVE_DEBUG_FILE_H


#ifdef __cplusplus
extern "C" {
#endif

void debug_printf(int level, const char *format, ...);
void debug_init(const char *filename, int level);
void debug_deinit();


#ifdef __cplusplus
}
#endif

#endif // ifndef HAVE_DEBUG_FILE_H
