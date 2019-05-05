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


#ifndef HAVE_MPM_H
#define HAVE_MPM_H


/* Vérification des switchs de compilation */
// MPM_GLIB_JSON MPM_JANSSON MPM_OPENSSL MPM_WINCRYPTO
#if ! (defined(MPM_GLIB_JSON) ^ defined(MPM_JANSSON))
#error Must define exactly one out of MPM_GLIB_JSON and MPM_JANSSON
#endif

#if ! (defined(MPM_OPENSSL) ^ defined(MPM_WINCRYPTO))
#error Must define exactly one out of MPM_OPENSSL and MPM_WINCRYPTO
#endif


#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#ifdef __linux__
#include <termio.h>
#include <unistd.h>
#endif


#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN32
#define STDIN_FILENO 0   /* ce qu'on a dans unistd.h sous linux */
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif


#include <errno.h>
#include <assert.h>


#include <inttypes.h> /* pour PRIx64 et autres, qui ne sont pas pas dans stdint.h */


#if defined(MPM_GLIB_JSON) 
#include <json-glib/json-glib.h>
#include <glib.h>
#include <glib-object.h>
#endif

#if defined(MPM_JANSSON)
#include <jansson.h>
#endif



#include <cparser.h>


#include <lib_sss.h>
#include <tdll.h>
#include <lb64.h>
#include "debug_file.h"
#include "messages_mpm.h"

#ifdef __cplusplus /* a ne pas charger dans les modules en C tout court */
#include "secret.h"
#include "database.h"
#include "holder.h"
#include "crypto_wrapper.h"
#endif /* __cpluplus */

// définie dans cli_callbacks.c mais appelée dans le main()
void cli_color_white_bg();
void cli_ansi_reset();
extern int cli_use_ansi;



#if defined(__linux__) && defined(DEBUG)
#include <mcheck.h>
#endif


//#define CLI_MAX_LEN 256


/* Article pour trouver les options préprocesseur par plateforme
https://stackoverflow.com/questions/4605842/how-to-identify-platform-compiler-from-preprocessor-macros
https://sourceforge.net/p/predef/wiki/Home/
 

Rappel C++
https://fr.wikipedia.org/wiki/C%2B%2B
https://fr.wikibooks.org/wiki/Programmation_C%2B%2B/Les_classes

Utilisation de pkconfiug pour générer le Makefile
$ pkg-config --cflags glib-2.0
 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include
$ pkg-config --libs glib-2.0
 -L/usr/lib -lm -lglib-2.0
https://developer.gnome.org/glib/stable/glib-compiling.html


Autocomplétion : bash utilise GNU-readline

ZLib :
http://www.zlib.net/manual.html

ZEXTERN int ZEXPORT uncompress OF((Bytef *dest, uLongf *destLen,
                                   const Bytef *source, uLong sourceLen));
				   

Codes ANSI pour couleurs sur le terminal
https://en.wikipedia.org/wiki/ANSI_escape_code


Generateur aléatoire avec OpenSSL
https://wiki.openssl.org/index.php/Random_Numbers



Explication sur les modes d'operation des chiffrements de blocs :
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation


Exemples d'implémentations de divers algos 256 bits :
http://embeddedsw.net/Cipher_Reference_Home.html



Guide pour un Makefile
http://nuclear.mutantstargoat.com/articles/make/


Guide pour compilation statique
https://www.systutorials.com/5217/how-to-statically-link-c-and-c-programs-on-linux-with-gcc/
http://insanecoding.blogspot.fr/2012/07/creating-portable-linux-binaries.html
Ordre des librairies
https://eli.thegreenplace.net/2013/07/09/library-order-in-static-linking


Macros prédéfinies standards
https://gcc.gnu.org/onlinedocs/cpp/Standard-Predefined-Macros.html


Identifier les sections dans le code
https://stackoverflow.com/questions/16552710/how-do-you-get-the-start-and-end-addresses-of-a-custom-elf-section-in-c-gcc


PM manager existant avec ssss
https://www.vaultproject.io/intro/index.html


*/


#endif /* HAVE_MPM_H */