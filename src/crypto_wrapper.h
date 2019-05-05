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


#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef __gnu_linux__
#include <sys/time.h>
#endif






// Utilisation de l'instruction rdrand pour accès au RNG hardware
#if (__GNUC_MAJOR__ > 4 || (__GNUC_MAJOR__ == 4 && __GNUC_MINOR__ >= 6))
#include <immintrin.h>
#define MPM_USE_RDRAND
#pragma message Instruction rdrand hardware disponible
#endif




#define MPM_SHA_ITERATIONS (65536) /* nombre de sha itérés pour la génération des marqueurs de chunk et clé de holder */
#define MPM_SHA_OFFSET_ITERATIONS (3*5*11*13*17) /* nombre premier avec MPM_SHA_ITERATIONS mais qui s'approche entre 1 et 2 tiers */

void random_init();
void random_deinit();
void *random_bytes(void *dest, size_t n);
char *generate_password(char *dest, int n);

void cw_aes_cbc(unsigned char *buffer, size_t len, unsigned char *key, unsigned char *iv, int enc);
void cw_sha256_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2);
void cw_sha256_iterated_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2);
void cw_sha256_mix2(unsigned char *result, unsigned char *salt, uint64_t common_magic);


#ifdef __cplusplus
}
#endif