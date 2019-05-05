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


#ifndef HAVE_HOLDER_H
#define HAVE_HOLDER_H

#include <stdint.h>
#include <stdlib.h>

#if defined(MPM_GLIB_JSON) 
#include <json-glib/json-glib.h>
#include <glib.h>
#include <glib-object.h>
#endif

#if defined(MPM_JANSSON)
#include <jansson.h>
#endif


#include "database.h"

#ifndef MPM_T_DATABASE_DECLARED /* forward definition pour éviter car holder/database se référencent l'un l'autre */
class t_database;
#endif


#define HOLDER_CHUNK_STATUS_NONE 1 /**< object en mémoire mais pas dans le fichier. Chunk à créer. Cas des holder ajoutées */
#define HOLDER_CHUNK_STATUS_CLOSED 2 /**< holder en mémoire, et sur disque, mais fermé. N'est pas éditable, et le chunk sera réécrit tel quel à la fermture du fichier  */
#define HOLDER_CHUNK_STATUS_OPEN 3 /**< holder en mémoire. Object éditable */
#define CHUNK_HOLDER_SIZE 512  /**< taille des chunk */
#define CHUNK_HOLDER_AES_SIZE (512-3*32) /**< longueur soumise à l'AES parmis les 512 */
#define CHUNK_HOLDER_AES_OFFSET (3*32) /**< offset à partir duquel on chiffre */
#define CHUNK_MAX_PARTS 8  /**< place disponible dans le chunk pour les parts, common+secret */

#define CHUNK_HOLDER_MAGIC 0x4425827a2cb0794b /**< nombre aléatoire fixe pour vérifier qu'un chunk holder est bien déchiffré */
#define CHUNK_HOLDER_VERSION 0x0000000000000001 /**< version encodée dans les chunks holder */

// Person chunk file structure
typedef struct t_chunk_holder {
	unsigned char salt1[32]; ///< sel utilisé pour la reconnaissance des chunks de holdernes et comme IV pour le chiffrement
	unsigned char hash[32];  ///< haché utilisé pour la reconnaissance des chunks = sha256(salt1 | password)
	unsigned char salt2[32]; ///< sel utilisé pour le chiffrement 
	
	/// \note Everything below is encoded with AES using pkey=SHA256(nickname | salt2 | password)
	
	unsigned char parts[CHUNK_MAX_PARTS*32];    ///< les parts. une holderne peut porter au maximum 8 parts common+secret
	uint64_t xparts[CHUNK_MAX_PARTS];	    ///< Les parts X
	uint16_t common_treshold; ///< Treshold pour l'accès public à la base. Nécessaire pour créer le sss 
	uint16_t common_nb_parts; ///< nombre de part que détient cette holderne pour l'accès "common"
	uint16_t secret_treshold; ///< Treshold pour l'accès aux champs privés
	uint16_t secret_nb_parts; ///< nombre de part que détient cette holderne pour l'accès "secret"
	uint64_t common_magic; ///< numéro choisi aléatoirement, pour la base, stocké dans chaque chunk peron, utilisé pour le chunk de repérage de la base common
	uint16_t id_holder;  ///< ID of this holder, reference to the common chunk

	unsigned char padding[56]; ///< Parce qu'on veut des chunks de 512 octets
			
	uint64_t version;    ///< Version du format de fichier 
	uint64_t magic;      ///< utilisé pour vérifier que le décodage a bien fonctionné. Car attention, on ne stocke pas le nickname ici...
} t_chunk_holder;

#define MPM_T_HOLDER_DECLARED
class t_holder {
	public:
		t_holder(char *nn, t_database *db_);
		t_holder(char *nn, t_database *db_, t_chunk_holder *chunk, int file_index_, unsigned char *pkey_);

		#ifdef MPM_GLIB_JSON
		t_holder(t_database *db_, JsonObject *jso);
		void complete_ouverture(JsonObject *jso);
		#endif

		#ifdef  MPM_JANSSON
		t_holder(t_database *db_, json_t *jso);
		void complete_ouverture(json_t *jso);
		#endif

		~t_holder();
		
		void load_chunk();		// Charge un holder depuis le fichier .upm
		void save_chunk(FILE *fichier);		// sauve une holderne dans le fichier .upm
		void load_common();		// Charge un holder d'après le container json common

		#ifdef MPM_GLIB_JSON		
		JsonNode *save_common();		// ajoute la holderne au container json common
		#endif
		#ifdef  MPM_JANSSON
		json_t *save_common();		// ajoute la holderne au container json common
		#endif
			
		void change_password(); // demande à la console pour changer un MdP
		void showDetails();	// Affiche à la console les informations de cette holder
		void getParts();	// Donne les parts
		int is_nickname(char *nn); // Teste si cet objet correspond à ce nickname
		char *get_email();
		void set_email(char *em);
		int get_nb_common();
		bool set_nb_common(int n);
		int get_nb_secret();
		bool set_nb_secret(int n);
		int get_id_holder();
		void set_password(char *mdp);
		int try_tardif(char *password);
		//char *prompt();
		bool test_password(char *mdp);
		//void compte_parts(int *common_total_, int *secret_total_, int *common_treshold_, int *secret_treshold_);
		void compte_parts_disponibles(int *common_, int *secret_);
		void compte_parts_distribuees(int *common_, int *secret_);
		void compte_parts_necessaires(int *common_, int *secret_);			
		char *nickname; ///< Le nickname de la holderne
		char *email; ///< L'email de la holderne, ou NULL si pas d'email
		uint16_t id_holder; ///< L'ID de la holderne, unique. Fixé à la création
		uint16_t chunk_status; ///< Où en est cette holderne par rapport à son chunk dans le fichier. Utilise les constantes HOLDER_CHUNK_STATUS_xxx
		unsigned char salt1[32]; ///< Pour le chunk - reconnaissance. Sera mis dans le chunk lors du save()
		unsigned char salt2[32]; ///< Pour le chunk - chiffrement
		unsigned char pkey[32];  ///< initialisé à SHA256(nickname | salt2 | password) à chaque chgt de MdP. N'est pas stocké dans le chunk.
		unsigned char hash[32];  ///< initialisé à sha256(salt1 | password) à chaque chgt de MdP - reconnaissance des chunks dans le fichier	
		bool password_set; ///< indique si le MdP a été initialisé, lors des créations de nouvelles holdernes
		unsigned char parts[CHUNK_MAX_PARTS*32];    ///< les parts. une holderne peut porter au maximum 8 parts common+secret
		uint64_t xparts[CHUNK_MAX_PARTS];	    ///< Les parts X
		unsigned char chunk[CHUNK_HOLDER_SIZE];	///< Le bloc dans le fichier MPM, déchiffré ou non selon chunk_status

		uint16_t common_nb_parts; ///< nombre de part que détient cette holder pour l'accès "common"
		uint16_t secret_nb_parts; ///< nombre de part que détient cette holder pour l'accès "secret"

		//uint16_t common_treshold; ///< quorum common tel que ce holder le connait. Initialisé à divers moment selon le mode de création du holder
		//uint16_t secret_treshold; ///< quorum secret tel que ce holder le connait. Initialisé à divers moment selon le mode de création du holder


		int file_index; ///< position du chunk dans le fichier. Réinitialisé pendant la sauvegarde
		t_database *db; ///< la database de rattachement. On en a besoin pour invoquer lsss_* par exemple
		
	private:	
		void emet_parts();
		
};


void *find_holder_chunk(FILE *f);


#endif /* HAVE_HOLDER_H  */