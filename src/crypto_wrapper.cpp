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



/**
 * \file crypto_wrapper.cpp
 * \brief Wrapper pour les fonctions de cryptographie
 * \note
 * - Utilise uniquement des types standard, et pas les struct. chaine \0 et unsigned char*
 * - Utilise openssl/libcrypto pour Linux
 * - le seul endroit où on doit invoquer libcrypto/openssl
 * - Fournit également la fonction de générateur aléatoire random_bytes()
 */
#include <stdio.h> /* pour stderr */
#include "crypto_wrapper.h"
//#define DEBUG
#include "debug_file.h"
#include <inttypes.h>

//#define MPM_WINCRYPTO

/* Note : utilisation de l'instriction rdrand avec GCC :
https://stackoverflow.com/questions/29372893/rdrand-and-rdseed-intrinsics-gcc-and-intel-c
https://en.wikipedia.org/wiki/RdRand
ci-dessus : sample ASM pour tester su l'instruction existe
Mais ne pas oublier avant de vérifier si cpuid existe (voir guide AMD64 n° 3)
*/



#ifdef MPM_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif

#ifdef MPM_WINCRYPTO
#define WIN32_NO_STATUS 

#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>  
/* pour le NT_SUCCESS et gestion NTSTATUS (beau bazar...)
   Voir : https://stackoverflow.com/questions/30721583/where-are-the-bcrypt-ntstatus-code-return-values-defined 
   et :   cet autre article sur le NT_STATUS : http://kirkshoop.blogspot.com/2011/09/ntstatus.html */

#include <wincrypt.h>
#include <bcrypt.h>
#include <malloc.h>
static BCRYPT_ALG_HANDLE hAlgorithm;
#endif



/** \brief Initialisation du générateur aléatoire 
 */
void random_init() {

	// Initialisation du rand() de la libc. En fait, sera inutilisé si MPM_WINCRYPTO ou MPM_OPENSSL
	#ifdef __gnu_linux__
	#pragma message ( "Utilisation de gettimeofday() avec srand()" )
	struct timeval tv;
	gettimeofday(&tv, NULL);
	#ifdef DEBUG
	srand(0);
	#else
	srand(tv.tv_usec);
	#endif
	#endif

	// Initialisation PRNG OpenSSL
	#ifdef MPM_OPENSSL 
	RAND_poll();
	#endif
	
	// Initialisation BCrypt de Windows
	#ifdef MPM_WINCRYPTO
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0 );
	if(!NT_SUCCESS(status)) {
		fprintf(stderr, "%s() %s:%d runtime error\n", __func__, __FILE__, __LINE__);
	}
		#ifdef DEBUG
		debug_printf(0,"random_init() API BCrypt/Windows ok\n");
		#endif
	#endif
	return;
}

/** \brief Libération des ressources du générateur aléatoire 
 */
void random_deinit() {

	#ifdef MPM_WINCRYPTO
	NTSTATUS status = BCryptCloseAlgorithmProvider(&hAlgorithm, 0 );
	if(!NT_SUCCESS(status)) {
		fprintf(stderr, "%s() %s:%d runtime error\n", __func__, __FILE__, __LINE__);
	}		
	#endif

	return;
}

/** \brief Remplit une zone mémoire d'octets aléatoires 
 *  \param[in]  dest   Le buffer à remplir
 *  \param[in]  n      Le nombre d'octets
 *  \note 
 *  - Fonctionne un peu comme memset()
 *  - Fonction à surcharger comme on peut, avec le meilleur génrateur disponible
 *  - random_init() et random_deinit() sont là pour initialiser le générateur si nécessaire
 */
void *random_bytes(void *dest, size_t n) {
	#ifdef MPM_OPENSSL 
			int rc = RAND_bytes((unsigned char*)dest, (int) n);
			if(rc != 1) {
				fprintf(stderr, "runtime error, SSL RAND_bytes()");
				abort();
			}
	
	#else
		#ifdef MPM_WINCRYPTO
			// https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/nf-bcrypt-bcryptgenrandom
    		NTSTATUS status= STATUS_UNSUCCESSFUL;
			status=BCryptGenRandom(hAlgorithm, (PUCHAR)dest, n, 	0 );
			if(!NT_SUCCESS(status)) {
				fprintf(stderr, "%s() %s:%d runtime error\n", __func__, __FILE__, __LINE__);
			}
		#else
			size_t i;
			unsigned char *d;
			d = (unsigned char*)dest;
			for (i=0;i<n;i++) {
				*d = (unsigned char)(rand() & 0xff);
				d++;
			}
			fprintf(stderr,"Warning: use of weak rand() standard function as random source\nThis is not a release-grade build\n");
		#endif
	#endif
	
	return dest;
}

/** \brief Génère un mot de passe aléatoire
 *  \param[in]  dest   Le buffer à remplir
 *  \param[in]  n      Le nombre d'octets
 *  \note 
 *  - l'appelant fournit le buffer, et prévoit qu'on ajoutera un \0 à la fin
 *  - MdP utilisant a..z A..Z 0..9
 */
char *generate_password(char *dest, int n) {
	char *d=dest;
	uint64_t b64;
	int b;
	for (int i=0; i<n; i++) {
		random_bytes((unsigned char*) &b64, sizeof(b64));
		b = b64 % 62;
		
		if (b<26) {
			b+= 'a';
		} else if (b<52) {
			b+= 'A' - 26;
		} else {
			b+= '0' - 52;
		}
		*d=b;
		d++;
	}
	*d=0;
	return dest;
}

/** \brief WinCrypto API only : Return a string correspondinf to NT_STATUS return by BCRypt*() */
#ifdef _WIN32
static char *NT_STATUS_str(NTSTATUS n) {

	fprintf(stderr, "STATUS_SUCCESS=%lx\n", STATUS_SUCCESS);
	fprintf(stderr, "STATUS_BUFFER_TOO_SMALL=%lx\n", STATUS_BUFFER_TOO_SMALL);
	fprintf(stderr, "STATUS_INVALID_HANDLE=%lx\n", STATUS_INVALID_HANDLE);
	fprintf(stderr, "STATUS_INVALID_PARAMETER=%lx\n", STATUS_INVALID_PARAMETER);
	fprintf(stderr, "STATUS_NOT_SUPPORTED=%lx\n", STATUS_NOT_SUPPORTED);
	
	n = NT_ERROR(n);
	if (n==STATUS_SUCCESS) return "STATUS_SUCCESS";
	if (n==STATUS_BUFFER_TOO_SMALL) return "STATUS_BUFFER_TOO_SMALL";	
	if (n==STATUS_INVALID_HANDLE) return "STATUS_INVALID_HANDLE";	
	if (n==STATUS_INVALID_PARAMETER) return "STATUS_INVALID_PARAMETER";
	if (n==STATUS_NOT_SUPPORTED) return "STATUS_NOT_SUPPORTED";
	return "NTSTATUS unknown";
}


#endif


/** \brief Chiffre/déchiffre une zone mémoire en AES256-CBC 
 *  \param[in,out] buffer   Le buffer contenant les données. Les données sont traitées en place
 *  \param[in]  len      Longueur à traiter. Sera arrondi au multiple de 16 supérieur
 *  \param[in]  key      Clé AES256 (= 32 octets)
 *  \param[in]  iv       Vecteur d'initialisation du CBC
 *  \param[in]  enc      0=déchiffre, 1=chiffre
 *  \note 
 *  - Le buffer doit prévoir que la longueur sera éventuellement arrondie au multiple de 16 supérieur. Il doit être assez grand
 *  - invoqué depuis plusieurs endroits
 *  \todo Traiter les erreurs en les remontant à l'appelant
 */
 
#ifdef MPM_OPENSSL 
void cw_aes_cbc(unsigned char *buffer, size_t len, unsigned char *key, unsigned char *iv, int enc) {
	EVP_CIPHER_CTX *chiffreur;
	
	len = (len+15)&(0xfffffffffffffff0); // aligne la longueur sur 16 octets
	
	unsigned char* dest = (unsigned char*) alloca(len+32);
	if (!(chiffreur = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "%s Runtime line %d file %s\n", __func__,  __LINE__, __FILE__);
		abort();
	}
	
	
	/* int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc); */
	if (EVP_CipherInit_ex(chiffreur, EVP_aes_256_cbc(), NULL, key, iv, enc) !=1) {
		fprintf(stderr, "%s Runtime line %d file %s\n", __func__,  __LINE__, __FILE__);
		abort(); 
	}
	EVP_CIPHER_CTX_set_padding(chiffreur,0);	
	
	/* int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl); */
	size_t len_out=0;
	size_t l=0; // Important. Car comme on caste le pointeur, qu'openssl attend en *int, pas forcément de même largeur...
	if (EVP_CipherUpdate(chiffreur, dest, (int*)&l, buffer, (int)len) !=1) {
		fprintf(stderr, "%s Runtime line %d file %s\n", __func__,  __LINE__, __FILE__);
		abort(); 
	}
	len_out+=l;
	
	if (EVP_CipherFinal_ex(chiffreur, buffer + len_out, (int*)&l ) != 1) {
		fprintf(stderr, "%s Runtime line %d file %s\n", __func__,  __LINE__, __FILE__);
		abort(); 
	}
	len_out+=l;	
	
	if (len_out != len) {
		fprintf(stderr, "%s() Runtime line %d - len_out=%ld len=%ld\n", __func__,  __LINE__, len_out, len);
		abort();	
	}
	memcpy(buffer, dest, len);
}
#endif /* MPM_OPENSSL */

#ifdef MPM_WINCRYPTO
// Exemple trouvé ici : https://docs.microsoft.com/en-us/windows/desktop/seccng/encrypting-data-with-cng
void cw_aes_cbc(unsigned char *buffer, size_t len, unsigned char *key, unsigned char *iv, int enc) {
	
    BCRYPT_ALG_HANDLE       hAesAlg                     = NULL;
    BCRYPT_KEY_HANDLE       hKey                        = NULL;
	PBYTE                   pbKeyObject                 = NULL;
	DWORD					cbKeyObject                 = 0,
							cbData                      = 0; /* pour contenir des lg en résultat, pas vraiment utilisé */
    NTSTATUS                status                      = STATUS_UNSUCCESSFUL;
	
	// Open an algorithm handle.
	if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();			
	}

	// Calculate the size of the buffer to hold the KeyObject.
    if(!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();			
	}

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    if(NULL == pbKeyObject) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();		
    }

	// Fixe le mode CBC
    if(!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, 
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();										
	}

	// Le buffer contenant l'IV sera modifié, donc on le recopie avant de l'utiliser
	// (curieuse coutume de l'API Wincrypt, onne sait pas ce qu'il met dedans)
	PUCHAR iv_temp = (PUCHAR)alloca(32);
	memcpy(iv_temp, iv, 32);

	// Generate the key from supplied input key bytes.
    if(!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, 
                                        (PBYTE)key, 32, 0))) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();									
	}
	
	// Chiffre proprement dit
	// Note sur l'API Windows : on peut avoir le buffer d'entrée et de sortie égaux
	// Si on ne donne pas de buffer de sortie, ça ne chiffre pas, mais ça calcule la taille nécessaire 
	// du buffer de sortie
	if (enc) {
		status = BCryptEncrypt(hKey, 
            buffer, len,  /* buffer d'entrée */
            NULL,         /* padding info */
            iv_temp, 32,  /* IV et len IV */
            buffer, len,  /* buffer de sortie */
            &cbData,      /* Contiendra le nb d'octets effectivement produits */ 
            0 /* flag. On demande pas de padding notamment */ );
	} else {
		status = BCryptDecrypt(hKey, 
            buffer, len,  /* buffer d'entrée */
            NULL,         /* padding info */
            iv_temp, 32,  /* IV et len IV */
            buffer, len,  /* buffer de sortie */
            &cbData,      /* Contiendra le nb d'octets effectivement produits */ 
            0 /* flag. On demande pas de padding notamment */ );		
	}
	
    if(!NT_SUCCESS(status)) {
		fprintf(stderr, "%s() Runtime line %s:%d\n", __func__,  __FILE__, __LINE__);
		abort();													
	}
	
	if (cbData != len) {
		fprintf(stderr, "%s() Runtime line %s:%d N'a pas chiffré le bon nombre d'octets\n", __func__,  __FILE__, __LINE__);
		abort();		
	}


cleanup: /* Libération des ressources */
 	if(hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg,0);
    }

    if (hKey)    
    {
        BCryptDestroyKey(hKey);
    }

    if(pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
}
#endif /* MPM_WINCRYPTO */


/** \brief Calcul d'un sha pour certaines opération avec les MdP, nickname et sels
 *  \param[in]  chaine1   Une chaine de caractères de longueur variable terminé par un \0
 *  \param[in]  salt      Un sel de 32 octets
 *  \param[in]  chaine2   Une chaine de caractères de longueur variable terminé par un \0
 *  \param[out] result    Le résultat = SHA256( chaine1 | salt[32] | chaine2 ))
 *  \note 
 *  - invoqué depuis t_holder::set_password()
 *  \todo gérer les erreurs libcrypto
 */
#ifdef MPM_OPENSSL 
void cw_sha256_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2) {
	SHA256_CTX hacheur;
	if (SHA256_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__, __LINE__);
		abort();
	}
	SHA256_Update(&hacheur, chaine1, strlen(chaine1));
	SHA256_Update(&hacheur, salt, 32);
	SHA256_Update(&hacheur, chaine2, strlen(chaine2));
	SHA256_Final(result, &hacheur);
}
#endif /* MPM_OPENSSL */

#ifdef MPM_WINCRYPTO
void cw_sha256_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2) {

	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_HASH_HANDLE hHash;

	NTSTATUS ret=BCryptOpenAlgorithmProvider( &hAlgorithm, L"BCRYPT_SHA1_ALGORITHM",  NULL,	0);
	if (ret != STATUS_SUCCESS) { 	fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); abort();	}	
	
	ret = BCryptCreateHash(
		hAlgorithm,
  		&hHash,
  		NULL, /* pbHashObject, laisser Windows allouer la mémoire nécessaire */
  		0,    /* cbHashObject, */
  		NULL, /* pbSecret, inutilisé */
  		0,    /* cbSecret, inutilisé */
  		0     /* dwFlags */
	);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }
	ret = BCryptHashData   (hHash, (unsigned char *)chaine1, strlen(chaine1), 0);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }	
	ret = BCryptHashData   (hHash, salt,    32,              0);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }
	ret = BCryptHashData   (hHash, (unsigned char *)chaine2, strlen(chaine2), 0);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }
	ret = BCryptFinishHash (hHash, result,  32,              0);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }
	ret = BCryptDestroyHash(hHash);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); 	abort(); }
}
#endif /* MPM_WINCRYPTO */


/** \brief Calcul d'un sha itéré pour certaines opération avec les MdP, nickname et sels
 *  \param[in]  chaine1   Une chaine de caractères de longueur variable terminé par un \0
 *  \param[in]  salt      Un sel de 32 octets
 *  \param[in]  chaine1   Une chaine de caractères de longueur variable terminé par un \0
 *  \param[out] result    Le résultat = SHA256( chaine1 | salt[32] | chaine2 ))
 *  \note 
 *  - invoqué depuis t_holder::set_password()
 *  \todo gérer les erreurs libcrypto
 */
#ifdef MPM_OPENSSL 
void cw_sha256_iterated_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2) {
	unsigned char* r = (unsigned char*)alloca(32);
	SHA256_CTX hacheur;
	unsigned char* buffer = (unsigned char*) malloc(32*MPM_SHA_ITERATIONS);
	
	if (SHA256_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__, __LINE__);
		abort();
	}
	SHA256_Update(&hacheur, chaine1, strlen(chaine1));
	SHA256_Update(&hacheur, salt, 32);
	SHA256_Update(&hacheur, chaine2, strlen(chaine2));
	SHA256_Final(r, &hacheur);	


	// Remplit le buffer des sha itérés
	for (int i=0; i<MPM_SHA_ITERATIONS; i++) {
		if (SHA256_Init(&hacheur) == 0) {
			fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__,__LINE__);
			abort();
		}
		SHA256_Update(&hacheur, chaine1, strlen(chaine1));
		SHA256_Update(&hacheur, r, 32);
		SHA256_Update(&hacheur, chaine2, strlen(chaine2));
		SHA256_Final(r, &hacheur);
		memcpy(&buffer[i*32], r, 32);	
	}
	
	// Calcule le sha final
	if (SHA256_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__,__LINE__);
		abort();
	}
	
	int ofs=0;
	for (int i=0; i<MPM_SHA_ITERATIONS; i++) {
		SHA256_Update(&hacheur, &buffer[ofs*32], 32);
		ofs+=MPM_SHA_OFFSET_ITERATIONS;
		if (ofs>MPM_SHA_ITERATIONS) ofs-=MPM_SHA_ITERATIONS;
	}
	SHA256_Final(result, &hacheur);
	free(buffer);
}
#endif /* MPM_OPENSSL */

#ifdef MPM_WINCRYPTO
void cw_sha256_iterated_mix1(unsigned char *result, char *chaine1, unsigned char *salt, char *chaine2) {
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_HASH_HANDLE hHash;
	unsigned char* buffer = (unsigned char*) malloc(32*MPM_SHA_ITERATIONS);
	unsigned char* r = (unsigned char*)alloca(32);

	NTSTATUS ret=BCryptOpenAlgorithmProvider( &hAlgorithm, BCRYPT_SHA256_ALGORITHM,  NULL,	0);
	if (ret != STATUS_SUCCESS) { 
		fprintf(stderr, "%s runtime error %s:%d %s \n", __func__, __FILE__, __LINE__, NT_STATUS_str(ret)); 
		fprintf(stderr, "%lx\n\n", ret);
		abort();	
	}	
	
	ret = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); abort();	}	


	ret = BCryptHashData   (hHash, (unsigned char *)chaine1, strlen(chaine1), 0);
	ret = BCryptHashData   (hHash, salt,                     32,              0);
	ret = BCryptHashData   (hHash, (unsigned char *)chaine2, strlen(chaine2), 0);
	ret = BCryptFinishHash (hHash, r,                        32,              0);

	// Remplit le buffer des sha itérés
	for (int i=0; i<MPM_SHA_ITERATIONS; i++) {
		ret = BCryptHashData   (hHash, (unsigned char *)chaine1, strlen(chaine1), 0);
		ret = BCryptHashData   (hHash, r,                        32,              0);
		ret = BCryptHashData   (hHash, (unsigned char *)chaine2, strlen(chaine2), 0);
		ret = BCryptFinishHash (hHash, r,                        32,              0);
		memcpy(&buffer[i*32], r, 32);	
	}

	int ofs=0;
	for (int i=0; i<MPM_SHA_ITERATIONS; i++) {
		ret = BCryptHashData   (hHash, &buffer[ofs*32], 32, 0);
		ofs+=MPM_SHA_OFFSET_ITERATIONS;
		if (ofs>MPM_SHA_ITERATIONS) ofs-=MPM_SHA_ITERATIONS;
	}
	ret = BCryptFinishHash (hHash, result, 32, 0);
	ret = BCryptDestroyHash(hHash);	
	free(buffer);
}
#endif /* MPM_WINCRYPTO */


/** \brief Calcul d'un sha pour certaines opérations avec la base common
 *  \param[in]  salt            Un sel de 32 octets
 *  \param[in]  common_magic    Le nonce choisi à la création de la base pour détecter le chunk common une fois le premier chunk holder ouvert
 *  \param[out] result          Le résultat = SHA256( chaine1 | salt[32] | chaine2 ))
 *  \note 
 *  - invoqué depuis t_database::save() pour calcul du haché pour le chunk marqueur de la base common
 *  \todo gérer les erreurs libcrypto
 */
#ifdef MPM_OPENSSL 
void cw_sha256_mix2(unsigned char *result, unsigned char *salt, uint64_t common_magic) {
	SHA256_CTX hacheur;

	if (SHA256_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__, __LINE__);
		abort();
	}
	SHA256_Update(&hacheur, salt, 32);
	SHA256_Update(&hacheur, &common_magic, sizeof(common_magic));
	SHA256_Final(result, &hacheur);
}
#endif /* MPM_OPENSSL */

#ifdef MPM_WINCRYPTO
void cw_sha256_mix2(unsigned char *result, unsigned char *salt, uint64_t common_magic) {
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_HASH_HANDLE hHash;

	NTSTATUS ret=BCryptOpenAlgorithmProvider( &hAlgorithm, BCRYPT_SHA256_ALGORITHM,  NULL,	0);
	if (ret != STATUS_SUCCESS) { 
		fprintf(stderr, "%s runtime error %s:%d %s \n", __func__, __FILE__, __LINE__, NT_STATUS_str(ret)); 
		fprintf(stderr, "%lx\n\n", ret);
		abort();	
	}	
	
	ret = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
	if (ret != STATUS_SUCCESS) { fprintf(stderr, "%s runtime error %s:%d\n", __func__, __FILE__, __LINE__); abort();	}	

	ret = BCryptHashData   (hHash, salt, 32, 0);
	ret = BCryptHashData   (hHash, (unsigned char*)&common_magic, sizeof common_magic, 0);
	ret = BCryptFinishHash (hHash, result, 32, 0);
	ret = BCryptDestroyHash(hHash);
}
#endif /* MPM_WINCRYPTO */
