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

#ifndef HAVE_SECRET_H
#define HAVE_SECRET_H


#include <stdint.h>
#include <tdll.h>



#if defined(MPM_GLIB_JSON) 
#include <json-glib/json-glib.h>
#include <glib.h>
#include <glib-object.h>
#endif

#if defined(MPM_JANSSON)
#include <jansson.h>
#endif


#define MPM_MAX_SECRET_ID 100000 /* ID maximum dans la base, = nombre maximum de secrets/folders */ 

class t_database;
class t_secret_folder;
class t_secret_item;


class t_secret_field {
	public:
	t_secret_field(char *field_name_, char *value_, t_secret_item *parent_secret_ );
	
	#ifdef MPM_GLIB_JSON
	t_secret_field(JsonObject *jso, t_secret_item *parent_secret_ );
	JsonNode *save();
	#endif
	#ifdef  MPM_JANSSON
	t_secret_field(json_t *jso, t_secret_item *parent_secret_ );
	json_t *save();
	#endif

	
	~t_secret_field();
	void update(char *value_);
	bool is_field_name(char *field_name_);
	char *get_field_name();
	char *get_value();



	/** Gestion des champs secrets */
	bool is_secret();
	bool is_piggy_banked();
	void set_secret(); ///< Transforme le champ en champ secret
	void update_piggy_bank(); ///< Comme update, mais met le champ en tire-lire 
	void set_common(); ///< Passe le champ en common, ie le déchiffre et le conserve non chiffré (= uniquement le chiffrement json/common)
	void break_piggy_bank(); ///< Sort le champ de la tire-lire


	private:
	char *field_name;
	char *value;
	bool secret;
	bool piggy_banked;
	unsigned char *session_key; // Seulement si valeur en tirelire
	t_secret_item *parent_secret;
	char *value_plain; ///< pour contenir le champ en clair, si celui-ci est 'secret'
	
	/** \todo Gérer le versionning */
};



class t_secret_item {
	friend class t_secret_field;

	public:
		t_secret_item(t_secret_folder* parent_, char* title_, uint32_t id_);
		
		

		#ifdef MPM_GLIB_JSON
		t_secret_item(JsonObject *jso, t_secret_folder* parent_);
		JsonNode *save();	// Ajouter le secret dans le container json common
		#endif
		#ifdef  MPM_JANSSON
		t_secret_item(json_t *jso, t_secret_folder* parent_);
		json_t *save();	// Ajouter le secret dans le container json common
		#endif		
		~t_secret_item();
		void load();	// Charge le secret depuis le container json common

		uint32_t get_id();
		char *get_title();
		void set_title(char *title_);
		char *get_field_value(char *field_name);
		bool field_exist(char *field_name);
		void delete_field(char *field_name);
		void update_field(char *field_name_, char *value_);
		void set_field_secret(char *field_name_);
		void set_field_common(char *field_name_);
		char *field_value(char *field_name);
		/*GList*/ tdllist *get_fields();
		unsigned char *get_aes_iv();
		unsigned char *get_aes_secret(); ///< va chercher la clé du niveau secret dans la DB parent

	private: 
		uint32_t id;
		char *title;
		t_secret_folder* parent;
		/*GList*/tdllist *fields;
		unsigned char aes_iv[16]; ///< pour servir de vecteur d'initialisation à tous les champs de ce secret

};


class t_secret_folder {
	friend class t_secret_item;

	public:
		t_secret_folder(t_secret_folder* parent_, const char* title_, uint32_t id_, t_database *db_); // Constructeur pour création interactive par l'utilisateur

		~t_secret_folder(); // libération propre des ressources

		#ifdef MPM_GLIB_JSON
		t_secret_folder(JsonObject *jso, t_secret_folder* parent_, t_database *db_); // à partir d'une entrée json
		JsonNode *save();	// Ajouter le secret dans le container json common
							// Note : on a aussi load(), mais en private, invoqué depuis un constructeur
		#endif
		#ifdef  MPM_JANSSON
		t_secret_folder(json_t *jso, t_secret_folder* parent_, t_database *db_);
		json_t *save();
		#endif


		// Fonction pour l'affichage du contenu du dossier. On a séparé l'affichage des entrées de secret et celle des sous-dossiers
		/*GList*/ tdllist *get_sub_folders();
		/*GList*/ tdllist *get_secrets();

		uint32_t get_id();
		char *get_title();
		void set_title(char* title_);
		char *get_title_path(); // renvoie le chemin complet des dossiers

		t_secret_folder *get_parent_folder();
		t_secret_folder *get_sub_folder_by_id(int id);
		t_secret_item *get_secret_by_id(int id);
		void add_sub_folder(t_secret_folder* nf);
		void add_secret_item(t_secret_item* secret);

		void delete_sub_folder(int id); ///< supression d'un sous dossier (utilise la fonction récursive delete_all() )
		void delete_secret_item(int id);

		bool is_id_free(uint32_t id_); //< parcours tout l'arbre pour voir si un ID est libre
		char *prompt(); ///< renvoie la chaine utilisée comme prompt dans le submode 
		bool is_empty(); ///< indique si le dossier contient quelque chose (utilisé pour la suppression)
		t_database *get_db(); ///< renvoie la DB principale

	private:
		//void load();	// Charge le secret depuis le container json common
		void delete_all(); ///< suppression récursive de tout le contenu

		t_secret_folder *parent; // NULL pour le dossier racine
		char* title;
		uint32_t id; // l'ID de dossier/item

		/*GList*/ tdllist* sub_folders; // Les sous-dossiers
		/*GList*/ tdllist* secrets; // les secrets contenus dans ce dossier
		t_database *db; ///< lien avec la base principale
};






#endif /* HAVE_SECRET_H */

