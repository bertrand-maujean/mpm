/** \file Light Base-64 library
 *  No dependancies, only standard lib. Suitable for cross-compiling
 */

#include "lb64.h"







static unsigned char *lb64_base = (unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char *lb64_reverse = NULL; // table de lookup inverse, 256 entrées


/** \brief Encode a binary object into a printable base-64 narrow string
 * \note :
 * - 'dest' buffer is allocated if NULL, and return as return value. If dest is not NULL, it must be large enough
 * - Allocated size may be a bit larger than necessary
 * - err is optional, can be NULL 
 * - dest is an asciiz string, source is a buffer/len byte array
 */
char *lb64_bin2string(const char* dest, unsigned char *source, size_t len, int *err_) {
	int nb_triplets = (len+2)/3; // Nombre total de triplets, dont le dernier sera éventuellement tronqué = nombre de blocs de 4 en sortie
	
	unsigned char a,b,c;
	uint8_t w,x,y,z;
	int err=LB64_OK;
	
	char *d;
	if (dest == NULL) {
		int ldest = 16+nb_triplets*4; // en fait, il n'y a guère que le \0 final à ajouter
		d = (char*)malloc(ldest);
		memset (d, 0, ldest);
	} else {
		d = (char*)dest;
	}
	char* rd=d;

	w=x=y=z=0;
	for (int i=0; i<nb_triplets; i++) {
		a =                source[3*i];
		b = (3*i+1<len) ? (source[3*i+1]) : (0);
		c = (3*i+2<len) ? (source[3*i+2]) : (0);	
	
		w = a >> 2;
		x = ((a & 3) << 4) | (b >> 4);
		y = ((b & 15) << 2) | ((c & 192) >> 6);
		z = c & 63;

		//if ((w|x|y|z)>63) abort();
		if (z>63) abort();
		if (y>63) abort();
		if (x>63) abort();
		if (w>63) abort();

		*d = lb64_base[w]; d++;
		*d = lb64_base[x]; d++;
		*d = (3*i+1 < len) ? lb64_base[y] : '='; d++;
		*d = (3*i+2 < len) ? lb64_base[z] : '='; d++;
	}

	*d=0; 
	if (err_) *err_=err;
	return rd;
}

/*
tty /dev/pts/3
dashb -outp /dev/pts/0
break lb64_bin2string
dashb expressions watch a
dashb expressions watch b
dashb expressions watch c
dashb expressions watch w
dashb expressions watch x
dashb expressions watch y
dashb expressions watch z
dashb expressions watch i
dashb expressions watch nb_triplets
dashb expressions watch dest
run
*/


void lb64_build_reverse() {
	if (lb64_reverse) return;
	lb64_reverse = (unsigned char*) malloc(256*sizeof(lb64_reverse[0]));

	for (int i=0; i<256; i++) {
		lb64_reverse[i] = LB64_INVALID_CODE;
	}

	for (int i=0; i<64; i++) {
		lb64_reverse[ lb64_base[i] ] = i;
	}

	lb64_reverse[ '=' ] = LB64_PADDING_CHAR;
	lb64_reverse[ ' ' ] = LB64_SPACE_CHAR;
	lb64_reverse[ '\n' ] = LB64_SPACE_CHAR;
	lb64_reverse[ '\r' ] = LB64_SPACE_CHAR;
}

/** \brief 
 * \note :
 * - 
 * - En cas d'erreur, les données éventuellement décodées restent disponibles. Il faut éventuellement libérer la mémoire allouée
 */
unsigned char *lb64_string2bin(unsigned char *dest, size_t *decoded_len_, size_t max_len, char *source, int *err_) {
	lb64_build_reverse();

	int source_len = strlen(source);
	bool malloced=false;
	size_t decoded_len=0;

	int err = LB64_OK;

	if (dest == NULL) {
		size_t malloc_size = (strlen(source)+3)*3/4;
		dest = (unsigned char*) malloc(malloc_size);
		memset(dest, 0, malloc_size);
		if (max_len > malloc_size) max_len = malloc_size;
		malloced=true;
	}
	unsigned char *d = dest;
	
	uint16_t w,x,y,z;
	unsigned char a,b,c;
	int nout; // nb d'octets en sortie de ce bloc
	char *s=source;

	bool encore=true;
	while ((*s) && (encore)) {
	
		while (lb64_reverse[*s]== LB64_SPACE_CHAR) s++;
		if ((*s) == '\0') { encore=false; break; }
		w = lb64_reverse[ *(s++) ];

		while (lb64_reverse[*s]== LB64_SPACE_CHAR) s++;
		if ((*s) == '\0') { encore=false; err=LB64_UNEXPECTED_END; break; }
		x = lb64_reverse[ *(s++) ];

		while (lb64_reverse[*s]== LB64_SPACE_CHAR) s++;
		if ((*s) == '\0') { encore=false; err=LB64_UNEXPECTED_END; break; }
		y = lb64_reverse[ *(s++) ];

		while (lb64_reverse[*s]== LB64_SPACE_CHAR) s++;
		//if ((*s) == '\0') { encore=false; err=LB64_UNEXPECTED_END; break; }
		z = lb64_reverse[ *(s++) ];
		
		if (( w==LB64_INVALID_CODE) || ( x==LB64_INVALID_CODE) || ( y==LB64_INVALID_CODE) || ( z==LB64_INVALID_CODE) ) {
			err=LB64_INVALID_CODE;
			break;
		}

		if ((w > 66) | (x>66) | (y>66) | (z> 66) ) {
			err=LB64_INVALID_CODE;
			break;
		}

		if (y == LB64_PADDING_CHAR) {
			nout = 1;
			y = 0;
			encore=false;
		} else if (z == LB64_PADDING_CHAR) {
			nout = 2;
			z = 0;
			encore=false;
		} else {
			nout = 3;
		}

		a = (w << 2) | ( x >> 4);
		b = ((x & 15) << 4) | (y >> 2);
		c = ( (y &3) << 6 ) | (z);

		*d=a; d++; nout--; decoded_len++;
		if (decoded_len == max_len) break;
		
		if (nout) {
			*d=b; d++; nout--; decoded_len++;
			if (decoded_len == max_len) break;
			
			if (nout) {
				*d=c; d++; nout--; decoded_len++;
				if (decoded_len == max_len) break;
			}
		}
	}
	if (decoded_len_) *decoded_len_ = decoded_len;
	if (err_) *err_=err;
	return dest;
}


/*

tty /dev/pts/4
dashb -outp /dev/pts/3
break lb64_string2bin
dashb expr watch a
dashb expr watch b
dashb expr watch c
dashb expr watch w
dashb expr watch x
dashb expr watch y
dashb expr watch z
dashb expr watch dest
dashb expr watch source
dashb history 
dashb ass
dashb thre
#dashb memory watch lb64_reverse 256

*/