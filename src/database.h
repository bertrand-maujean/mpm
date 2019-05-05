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


/** \file Fichier d'entête pour la classe t_database */

#ifndef HAVE_DATABASE_H
#define HAVE_DATABASE_H


//#include "mpm.h"

#include <stdint.h>

#if defined(MPM_GLIB_JSON) 
#include <json-glib/json-glib.h>
#include <glib.h>
#include <glib-object.h>
#endif

#if defined(MPM_JANSSON)
#include <jansson.h>
#endif

#include <lib_sss.h>
#include <tdll.h>
#include "holder.h"
#include "secret.h"
#include "debug_file.h"
#include "crypto_wrapper.h"


// Dépendance circulaire pénible...
//struct t_chunk_holder;
//class t_holder;


//! @name MPM_LEVEL_xxx Définition des états possibles d'ouverture de la base
//!@{
//!  
#define MPM_LEVEL_INIT 0 /**< Base vide pas encore initialisée */
#define MPM_LEVEL_NONE 1 /**< Base non ouverte, ne peut pas être encore différenciée d'une suite d'octets aléatoires */
#define MPM_LEVEL_FIRST 2 /**< Au moins un utilisateur a été reconnu, mais pas encore de quorum "common" */
#define MPM_LEVEL_COMMON 3 /**< Base ouverte, on a le quorum "common" */
#define MPM_LEVEL_SECRET 4 /**< Base complètement ouverte, on a le quorum "secret" */ 
//!@}

//!@{
//! Définition des états de base changée (pour savoir si on doit sauvegarder 
#define MPM_CHANGED_PASSWORD 1 /**< un utilisateur en état ouvert a changé son MdP */
#define MPM_CHANGED_SECRET 2 /**< un secret a été modifié */
#define MPM_CHANGED_HOLDER 4 /**< un porteur a été ajouté ou supprimé, ou a changé un attribut mail/nb parts...  */
#define MPM_CHANGED_NEW 8 /**< la base vient d'être créée, n'a jamais été écrite */
#define MPM_CHANGED_OTHER 16 /**< une information d'autre nature a été changée */
//!@}

//!@{
//! Code de retour pour la fonction try()
#define MPM_TRY_OK 0 /**< réussi */ 
#define MPM_TRY_NOT_FOUND 1 /**< nickname/MdP non trouvé dans la base, MdP incorrect */ 
#define MPM_TRY_ALREADY_OPENED 2 /**< nickname déjà ouvert */ 
#define MPM_TRY_INCONSISTENT 3 /**< Incohérence dans le fichier ou la base */ 
//!@}



// Chunk pour repérer la position de la base principale après les chunks holders
typedef struct t_common_marker {
	unsigned char salt[32]; // Sel utilisé pour la reconnaissance du marqueur, et comme vecteur d'init CBC de l'AES
	unsigned char hash[32];  // = sha256(salt | common_magic)
} t_common_marker;



#ifndef MPM_T_HOLDER_DECLARED /* forward declaration car holder/database se référencent l'un l'autre */
struct t_chunk_holder;
class t_holder;
#endif

// Classe principale pour gérer la base en mémoire
#define MPM_T_DATABASE_DECLARED
class t_database {
	friend class t_holder; // pour accès aux variables private

	public:
		t_database();
		t_database(int common_treshold_, int secret_treshold, char *filename);
		~t_database();
		
		char *prompt();
		void save();
		t_chunk_holder *find_chunk_holder(char *nickname, char *password, int *file_index, unsigned char *pkey); // Essaie de rechercher une holderne dans les chunks holder
		int get_stats(); // 
		int get_next_id_holder(); 
		void set_filename(char *fn);
		lsss_ctx *sss_common; // Les instances de partage de secret
		lsss_ctx *sss_secret;
		t_holder *find_holder(char *nickname);
		int is_changed();
		void set_changed(int flag);
		void check_level(); 
		//void compte_parts(int *common_total_, int *secret_total_, int *common_treshold_, int *secret_treshold_);
		void compte_parts_disponibles(int *common_, int *secret_);
		void compte_parts_distribuees(int *common_, int *secret_);
		void compte_parts_necessaires(int *common_, int *secret_);	
		void open_common();
		void open_secret();
		void read_common();
		#ifdef MPM_GLIB_JSON
		void read_json(JsonNode *node);
		#endif
		#ifdef  MPM_JANSSON
		void read_json(json_t *node);
		#endif
		
		int try_nickname(char *nickname, char *password, int *apporte_common, int *apporte_secret);
		t_secret_folder *get_root_folder();
		t_secret_folder *get_current_folder();
		
		uint32_t get_free_id();
		int get_status();

	//private: // solution de facilité...
		char *filename; ///< Le nom de fichier de la base sur disque
		#ifdef MPM_GLIB_JSON
		JsonNode *json_root_node; ///< utilisé pour la lecture et la sauvegarde (TODO : à remplacer par variable local des méthodes concernées) 
		#endif
		#ifdef  MPM_JANSSON
		json_t *json_root_node;
		#endif
		//GList *holders; ///< Liste des holders
		tdllist *holders; ///< Liste des holders
		t_secret_folder *root_folder; ///< Le dossier racine des secrets
		t_secret_folder *current_folder; ///< Le dossier courant des secrets
		t_secret_folder *set_current_folder(t_secret_folder *current_folder_); ///< Change le dossier courant

		int status; ///< Etat d'ouverture de la base. Constantes MPM_LEVEL_xxxx
		int common_treshold; ///< treshold pour ouvrir le niveau common
		int secret_treshold; ///< treshold pour ouvrir le niveau secret
		int next_id_holder; ///< prochain ID de holderne à attribué. Commence à 1 à la création d'une nouvelle base vide. Toujours incrémenté, jamais remis à 0. Sauvé dans la base common pour garantir l'unicité au delà des ouvertures/fermetures de la base
		int nb_holders; ///< Nombre de holdernes
		int changed; ///< Indicateur de changement. 0=pas de changement, constantes MPM_CHANGED_xxxx
		uint64_t common_magic; ///< Nonce déterminé aléatoirement à la création de la base, utilisé comme sel dans le hash de répérage du chunk common
		unsigned char common_key[32]; ///< la clé de la base common/json
		unsigned char secret_key[32]; ///< la clé des secrets
};





#endif /* HAVE_DATABASE_H */