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


#include "secret.h"
#include "database.h" /* nécessaire pour les niveaux MPM_LEVEL_ */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lb64.h>
#include <cparser.h> /* pour CPARSER_MAX_PROMPT */

#if defined(__linux__) && defined(DEBUG)
#include <mcheck.h>
#endif



/***************************************************************************
 * Classe t_secret_field::
 ***************************************************************************/

t_secret_field::t_secret_field(char *field_name_, char *value_, t_secret_item *parent_secret_ ) {
	field_name = strdup(field_name_);
	if (value_) {
		value=strdup(value_);
	} else {
		value=NULL;
	}
	parent_secret = parent_secret_;
	piggy_banked = false;
	secret=false;
	value_plain=NULL;
	session_key=NULL;	
}

#ifdef MPM_GLIB_JSON
t_secret_field::t_secret_field(JsonObject *jso, t_secret_item *parent_secret_ ) {
	parent_secret = parent_secret_;
	value_plain=NULL;

	// Récupère le nom de champ
	char *nn = (char*)json_object_get_string_member (jso, "field_name");
	if (nn == NULL) {
		printf("%s() Runtime : missing 'field_name' fields in json stream\n");
		field_name=strdup("(runtime error: noname)");
	}
	field_name = strdup(nn);

	// Récupère la valeur
	if (json_object_has_member(jso, "value")) {
		value=strdup((char*)json_object_get_string_member (jso, "value"));
	} else {
		value=NULL;
	}

	// Etat 'secret'
	if (json_object_has_member(jso, "secret")) {
		secret = (strcmp((char*)json_object_get_string_member (jso, "secret"),"true")==0);
	} else {
		printf("%s() Runtime : missing 'secret' fields in json stream\n");
		secret=false;
	}
	
	
	// Etat 'piggy_banked'
	if (json_object_has_member(jso, "piggy_banked")) {
		piggy_banked = (strcmp((char*)json_object_get_string_member (jso, "piggy_banked"),"true")==0);
	} else {
		printf("%s() Runtime : missing 'piggy_banked' fields in json stream\n");
	}
	

	//unsigned char *session_key; 
	if (json_object_has_member(jso, "session_key")) {
		session_key=(unsigned char*)strdup((char*)json_object_get_string_member (jso, "session_key"));
	} else {
		session_key=NULL;
	}	
}
#endif
#ifdef  MPM_JANSSON
t_secret_field::t_secret_field(json_t *jso, t_secret_item *parent_secret_ ) {
	parent_secret = parent_secret_;
	value_plain=NULL;

	// Récupère le nom de champ
	json_t *jsfn = json_object_get(jso, "field_name");
	const char *nn = json_string_value(jsfn);
	if ((nn == NULL) || (jsfn == NULL)) {
		printf("%s() Runtime : missing 'field_name' fields in json stream\n", __func__);
		field_name=strdup("(runtime error: noname)");
	}
	field_name = strdup(nn);
	
	// Récupère la valeur
	json_t *jsv = json_object_get(jso, "value");
	const char *v = json_string_value(jsv);
	if ((v!=NULL)&&(jsv!=NULL)) {
		value=strdup(v);
	} else {
		value=NULL;
	}

	// Etat 'secret'
	json_t *jses = json_object_get(jso, "secret");
	const char *sec = json_string_value(jses);
	if ((jses) && (sec)) {
		secret = (strcmp(sec,"true")==0);
	} else {
		printf("%s() Runtime : missing 'secret' fields in json stream\n", __func__);
		secret=false;
	}

	
	// Etat 'piggy_banked'
	json_t *jspb = json_object_get(jso, "piggy_banked");
	const char *pbs = json_string_value(jspb);
	if ((jspb) && (pbs)) {
		piggy_banked = (strcmp(pbs,"true")==0);
	} else {
		printf("%s() Runtime : missing 'piggy_banked' fields in json stream\n", __func__);
	}

	//unsigned char *session_key; 
	json_t *jssk = json_object_get(jso, "session_key");
	const char *sk = json_string_value(jssk);
	if ((jssk)&&(sk)) {
		session_key=(unsigned char*)strdup(sk);
	} else {
		session_key=NULL;
	}	
}
#endif


t_secret_field::~t_secret_field() {
	if (value) {
		memset(value, 0, strlen(value));
		free(value);
	}
	if (field_name) {
		memset(field_name, 0, strlen(field_name));
		free(field_name);
	}
	if (session_key) {
		memset(session_key, 0, 32);
		free(session_key);
	}	
	if (value_plain) {
		memset(value, 0, strlen(value_plain));
		free(value_plain);
	}
}


/** \Met à jour, ou fixe, la valeur du champ
 * \note Si le champ est NULL, il est malloc()é. Sinon, la précédente version est free()ée, puis re-malloc() 
 * \note Si c'est un champ secret :
 * - Change l'indicateur 'secret'
 * - Aligne le contenu sur un bloc de 16 octets
 * - Le chiffre AES-CBC sans padding
 * - L'encode base64
 */
void t_secret_field::update(char *value_) {
	if (value) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() suppression de la valeur précedente\n", __func__, __FILE__, __LINE__);
		#endif
		memset(value, 0, strlen(value));
		free(value);
		value=NULL;
	}
	if (secret) {
		#if defined(DEBUG)
		debug_printf(0,(char*)"%s() %s:%d update en mode secret value=%s\n", __func__, __FILE__, __LINE__, value_);
			#if defined(__linux__)
			mcheck_check_all();
			#endif
		#endif
		/// \todo Gérer l'update d'un champ secret
		size_t aes_len = ((strlen(value_)+1)+15) & (~0xf); // arrondi au bloc de 16 supérieur
		unsigned char* aes_buffer = (unsigned char*) alloca(aes_len);
		random_bytes(aes_buffer, aes_len);
		int err;
		strcpy((char*)aes_buffer, value_);

		#ifdef DEBUG
		debug_printf(0,(char*)"%s() %s:%d aes_buffer avant chiffrement=%s aes_len=%d\n", __func__, __FILE__, __LINE__, (char*)aes_buffer, aes_len);
			#if defined(__linux__)
			mcheck_check_all();
			#endif
		#endif

		cw_aes_cbc(aes_buffer, aes_len, parent_secret->get_aes_secret(), parent_secret->get_aes_iv(), 0);
	
		value = lb64_bin2string(NULL, aes_buffer, aes_len, &err); // laisse lb64 faire le malloc()
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() résultat lb64_bin2string() : %s\n", __func__, value);
			#if defined(__linux__)
			mcheck_check_all();
			#endif
		#endif

		if (err != LB64_OK) {
			fprintf(stderr, "Runtime error\n");
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() f=%s l=%d lb64_bin2string() a renvoyé une erreur\n", __func__, __FILE__, __LINE__);
			#endif
		}
	} else {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() update en mode common\n", __func__, __FILE__, __LINE__);
			#if defined(__linux__)
			mcheck_check_all();
			#endif
		#endif
		value=strdup(value_);
	}
	parent_secret->parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}

bool t_secret_field::is_field_name(char *field_name_) {
	if (field_name == NULL) {
		printf("%s() line %d Runtime error\n", __func__, __LINE__ );
	}
	return (strcmp(field_name, field_name_) == 0);
}

char *t_secret_field::get_field_name() {
	return field_name;
}

char *t_secret_field::get_value() {
	if (secret) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() sur un champ secret\n", __func__, __FILE__, __LINE__);
		#endif
		size_t b64_len = strlen(value);
		int err;
		size_t len;

		if (value_plain) {
			memset(value_plain, 0, strlen(value_plain));
			free(value_plain);
			value_plain=NULL;
		}
		
		// Ce buffer va contenir la valeur decodé b64, puis l'AES va travailler dedans par blocs de 16
		// Donc longueur malloc()ée en conséquence
		value_plain = (char*) malloc(48+(b64_len*4/3));	 

		#ifdef DEBUG
		debug_printf(0,(char*)"%s() b64=%s secret key=%lx iv=%lx\n", __func__, value, *(uint64_t*) parent_secret->get_aes_secret(), *(uint64_t*) parent_secret->get_aes_iv());
			#ifdef __linux__
			mcheck_check_all();
			#endif
		#endif		
		value_plain = (char*)lb64_string2bin((unsigned char*)value_plain, &len, b64_len, value, &err); 
		if (err != LB64_OK) {
			fprintf(stderr, "Runtime error\n");
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() f=%s l=%d lb64_string2bin() a renvoyé une erreur\n", __func__, __FILE__, __LINE__);
				#ifdef __linux__
				mcheck_check_all();
				#endif
			#endif
		}	
		if ((len & 0xf) != 0) {
			fprintf(stderr, "Runtime error\n");
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() f=%s l=%d lb64_string2bin() longueur décodée non multiple de 16\n", __func__, __FILE__, __LINE__);
				#ifdef __linux__
				mcheck_check_all();
				#endif
			#endif
		}
		cw_aes_cbc((unsigned char*)value_plain, len, parent_secret->get_aes_secret(), parent_secret->get_aes_iv(), 1);
		#if defined(__linux__) && defined(DEBUG)
		mcheck_check_all();
		#endif

		
		debug_printf(0,(char*)"%s() value_plain=%s\n", __func__, value_plain);
		return value_plain;
	} else {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() sur un champ common\n", __func__, __FILE__, __LINE__);
		#endif
		return value;	
	}
}

bool t_secret_field::is_secret() {
	return secret;
}

bool t_secret_field::is_piggy_banked() {
	return piggy_banked;
}


#ifdef MPM_GLIB_JSON
JsonNode *t_secret_field::save() {
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() title=%s value=%s\n", __func__, field_name, (value==NULL ? "(null)" : value));
	#endif

	JsonObject *object = json_object_new();
	json_object_set_member (object, "field_name",      json_node_init_string (json_node_alloc (), field_name));
	json_object_set_member (object, "secret",          json_node_init_string (json_node_alloc (), (secret ? "true" : "false")));
	json_object_set_member (object, "piggy_banked",    json_node_init_string (json_node_alloc (), (piggy_banked ? "true" : "false")));

	if (value) 
	json_object_set_member (object, "value",           json_node_init_string (json_node_alloc (), value));
	if (session_key) 
	json_object_set_member (object, "session_key",     json_node_init_string (json_node_alloc (), (const char*)session_key));

	return json_node_init_object (json_node_alloc (), object);
}
#endif
#ifdef  MPM_JANSSON
json_t *t_secret_field::save() {
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() title=%s value=%s\n", __func__, field_name, (value==NULL ? "(null)" : value));
	#endif

	json_t *jso = json_object();
	json_object_set(jso, "field_name",      json_string(field_name));
	json_object_set(jso, "secret",          json_string((secret ? "true" : "false")));
	json_object_set(jso, "piggy_banked",    json_string((piggy_banked ? "true" : "false")));
	if (value) 
	json_object_set(jso, "value",           json_string (value));
	if (session_key) 
	json_object_set(jso, "session_key",     json_string ((const char*)session_key));
	return jso;
}
#endif





/**
 * \brief Passe ce champ en mode 'secret'
 */
void t_secret_field::set_secret() {
	if (secret) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() champ déjà secret\n", __func__, __FILE__, __LINE__);
		#endif	
		return; // Le champ est déjà secret
	}
	if (parent_secret->parent->get_db()->get_status()!=MPM_LEVEL_SECRET) {
		fprintf(stderr, "Runtime error\n");
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() f=%s l=%d Erreur : status != MPM_LEVEL_SECRET\n", __func__, __FILE__, __LINE__);
		#endif	
		return;
	}

	if (value == NULL) {
		fprintf(stderr, "Runtime error\n");
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() f=%s l=%d value==NULL\n", __func__, __FILE__, __LINE__);
		#endif	
		return;
	}

	char* value_plain = value; // nb : assignation de pointeur
	value=NULL;
	secret = true;
	update(value_plain);
	free(value_plain);
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() en sortie de fonction, value=%s\n", __func__, value);
	#endif	
}


void t_secret_field::update_piggy_bank() {
}


void t_secret_field::set_common() {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() f=%s l=%d Fonction pas implémentée\n", __func__, __FILE__, __LINE__);
		#endif	
}



void t_secret_field::break_piggy_bank() {
// unsigned char *session_key;
}

/***************************************************************************
 * Classe t_secret_item::
 ***************************************************************************/
t_secret_item::t_secret_item(t_secret_folder* parent_, char* title_, uint32_t id_) {
	id=id_;
	title=strdup(title_);
	parent=parent_;	
	fields=NULL;
	
	update_field((char*)"user", (char*)"duchnok");
	update_field((char*)"url", (char*)"http://bidule.truc.tld");
	update_field((char*)"pwd", (char*)"kjjkhjhjklhjcnszopckl");
	
	random_bytes(aes_iv, 16);
}

#ifdef MPM_GLIB_JSON
t_secret_item::t_secret_item(JsonObject *jso, t_secret_folder* parent_) {
	parent = parent_;

	// Récupération du titre
	char *s = (char*)json_object_get_string_member (jso, "title");
	if (s == NULL) {
		printf("%s() Runtime : missing 'title' fields in json stream\n");
	}
	title = strdup(s);

	// Récupération de l'ID
	if (json_object_has_member(jso, "id")) {
		id=json_object_get_int_member (jso, "id");
	} else {
		printf("%s() Runtime : missing 'id' fields in json stream\n");
		id=-1;
	}

	// (char*)json_object_get_string_member (jso, "field_name")
	fields=NULL;
	GList* gl = json_array_get_elements (json_object_get_array_member (jso, "fields"));
	for ( ; gl != NULL; gl=gl->next) {
		//fields = g_list_append(fields, new t_secret_field(json_node_get_object ((JsonNode*)gl->data), this));
		fields = tdll_append(fields, new t_secret_field(json_node_get_object ((JsonNode*)gl->data), this));
	}
	
	// Récupération de l'IV AES
	if (json_object_has_member(jso, "aes_iv")) {
		char* aes_iv_b64= (char*) json_object_get_string_member (jso, "aes_iv");
		int err;
		size_t len;
		lb64_string2bin(aes_iv, &len, 16, aes_iv_b64, &err);
		
		if (len != 16) {
			fprintf(stderr, "runtime error\n");	;
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() ligne %d base64 decoded AES IV not 16 bytes long\n", __func__, __LINE__);
			#endif			
		}
		if (err != LB64_OK) {
			fprintf(stderr, "runtime error\n");	
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() ligne %d lb64_string2bin() a renvoyé une erreur\n", __func__, __LINE__);
			#endif	
		}	
	} else {
		fprintf(stderr, "runtime error\n");
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() ligne %d missing 'aes_iv' fields in json stream - Regenerating\n", __func__, __LINE__);
		#endif	
		random_bytes(aes_iv, 16);;
	}
}
#endif

#ifdef  MPM_JANSSON
t_secret_item::t_secret_item(json_t *jso, t_secret_folder* parent_) {
	parent = parent_;

	// Récupération du titre
	json_t *jst = json_object_get(jso, "title");
	const char *s = json_string_value(jst);
	if ((s == NULL)||(jst == NULL)) {
		printf("%s() Runtime : missing 'title' fields in json stream\n", __func__);
		s = "(error title NULL)";
	}
	title = strdup(s);

	// Récupération de l'ID
	json_t *jsid = json_object_get(jso, "id");
	if (jsid) {
		id=json_integer_value(jsid);
	} else {
		printf("%s() Runtime : missing 'id' fields in json stream\n", __func__);
		id=-1;
	}


	
	fields=NULL;
	json_t *jsfa = json_object_get(jso, "fields");
	int n = json_array_size(jsfa);
	for (int i=0; i<n; i++) {
		json_t *jsf = json_array_get(jsfa, i);
		fields = tdll_append(fields, new t_secret_field(jsf, this));
	}
		
	// Récupération de l'IV AES
	json_t *jsaesiv = json_object_get(jso, "aes_iv");
	if (jsaesiv) {
		const char* aes_iv_b64=json_string_value(jsaesiv);
		int err;
		size_t len;
		lb64_string2bin(aes_iv, &len, 16, (char*)aes_iv_b64, &err);
		
		if (len != 16) {
			fprintf(stderr, "runtime error\n");	;
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() ligne %d base64 decoded AES IV not 16 bytes long\n", __func__, __LINE__);
			#endif			
		}
		if (err != LB64_OK) {
			fprintf(stderr, "runtime error\n");	
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() ligne %d lb64_string2bin() a renvoyé une erreur\n", __func__, __LINE__);
			#endif	
		}		
		
	} else {
		fprintf(stderr, "runtime error\n");
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() ligne %d missing 'aes_iv' fields in json stream - Regenerating\n", __func__, __LINE__);
		#endif	
		random_bytes(aes_iv, 16);;		
	}
}
#endif



uint32_t t_secret_item::get_id() {
	return id;
}
char *t_secret_item::get_title() {
	return title;
}

void t_secret_item::set_title(char *title_) {
	if (title) {
		memset(title, 0, strlen(title));
		free(title);
	}
	title = strdup(title_);
	parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}

unsigned char *t_secret_item::get_aes_iv() {
	return aes_iv;
}
/**
 * \brief libération des ressources du secret item
 * \todo Ecrire le destructeur de t_secret_item. LIbérer les fields, mais aussi la GList elle-même
 */
t_secret_item::~t_secret_item() {
	// Libère les champs de secret
	for (/*GList*/ tdllist *f=fields; f; f=f->next) {
		delete (t_secret_field*)f->data;
		f->data = NULL;
	}
	//g_list_free(fields);
	tdll_free(fields);
	fields=NULL;
	
	// Puis le titre
	if (title) {
		memset(title, 0, strlen(title));
		free(title);
	}
}

void t_secret_item::update_field(char *field_name_, char *value_) {
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name_)) {
			((t_secret_field*)gl->data)->update(value_);
			return;
		}
	}
	//fields = g_list_append(fields, new t_secret_field(field_name_, value_, this));
	fields = tdll_append(fields, new t_secret_field(field_name_, value_, this));
	parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}

/*GList*/ tdllist *t_secret_item::get_fields() {
	return fields;
}



char *t_secret_item::get_field_value(char *field_name) {
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name)) {
			return ((t_secret_field*)gl->data)->get_value();
		}
	}
	return NULL;
}

bool t_secret_item::field_exist(char *field_name) {
	if (field_name == NULL) return false;
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name)) {
			return true;
		}
	}
	return false;
}

void t_secret_item::delete_field(char *field_name) {
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name)) {
			delete (t_secret_field*)gl->data;
			//fields = g_list_delete_link(fields, gl);
			fields = tdll_delete_link(fields, gl);
			return;
		}
	}
	parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}


/** \brief Export d'un secret en json
 */
#ifdef MPM_GLIB_JSON
JsonNode *t_secret_item::save() {
	JsonObject *object = json_object_new();
	json_object_set_member (object, "title",      json_node_init_string (json_node_alloc (), title));	
	json_object_set_member (object, "id",         json_node_init_int (json_node_alloc (), id));	

	// Traitement de la liste des champs
	JsonArray* json_array = json_array_new();
	for (/*GList*/ tdllist* gl = fields; gl != NULL; gl=gl->next) {
		json_array_add_element(json_array, ((t_secret_field*)gl->data)->save());
	}
	json_object_set_member (object, "fields",     json_node_init_array (json_node_alloc (), json_array));	

	// Envoie l'IV AES
	char b64[32];
	int err;
	json_object_set_member (object, "aes_iv",     json_node_init_string (json_node_alloc (), lb64_bin2string(b64, aes_iv, 16, &err) ));

	if (err != LB64_OK) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() lb64_bin2string() a renvoyé une erreur\n", __func__);
		#endif
		abort();
	}

	return json_node_init_object (json_node_alloc (), object);
}
#endif
#ifdef  MPM_JANSSON
json_t *t_secret_item::save() {
	json_t* jso = json_object();
	json_object_set(jso, "title",    json_string (title));
	json_object_set(jso, "id",       json_integer(id));
		
	// Traitement de la liste des champs
	json_t *jsfa = json_array();
	for (tdllist* gl = fields; gl != NULL; gl=gl->next) {
		json_array_append(jsfa, ((t_secret_field*)gl->data)->save());
	}
	json_object_set(jso, "fields", jsfa);	

	// Envoie l'IV AES
	char b64[32];
	int err;
	json_object_set(jso, "aes_iv", json_string(lb64_bin2string(b64, aes_iv, 16, &err) ));
	if (err != LB64_OK) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() lb64_bin2string() a renvoyé une erreur\n", __func__);
		#endif
		abort();
	}
	
	return jso;
}
#endif


unsigned char *t_secret_item::get_aes_secret() {
	//t_secret_folder* parent;
	return parent->db->secret_key;
}


/**
 * \brief Passe un champ existant en mode 'secret'
 * \note Appelle essentiellement t_secret_fiedl::set_secret()
 */
void t_secret_item::set_field_secret(char *field_name_) {
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name_)) {
			((t_secret_field*)gl->data)->set_secret();
		}
	}
	parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}

/**
 * \brief Passe un champ existant en mode 'common'
 * \note Appelle essentiellement t_secret_fiedl::set_secret()
 */
void t_secret_item::set_field_common(char *field_name_) {
	for (/*GList*/ tdllist* gl=fields; gl; gl=gl->next) {
		if (((t_secret_field*)gl->data)->is_field_name(field_name_)) {
			((t_secret_field*)gl->data)->set_common();
		}
	}
	parent->get_db()->set_changed(MPM_CHANGED_SECRET);
}

	

	 

/***************************************************************************
 * Classe t_secret_folder
 ***************************************************************************/
t_secret_folder::t_secret_folder(t_secret_folder* parent_, const char* title_, uint32_t id_, t_database *db_) {
	parent=parent_;
	title=strdup(title_);
	sub_folders=NULL;
	secrets=NULL;
	id=id_;
	db=db_;
}

#ifdef MPM_GLIB_JSON
t_secret_folder::t_secret_folder(JsonObject *jso, t_secret_folder* parent_, t_database *db_) {
	parent = parent_;
	db=db_;

	// Récupération du titre
	char *s = (char*)json_object_get_string_member (jso, "title");
	if (s == NULL) {
		printf("%s() Runtime : missing 'title' fields in json stream\n");
		title =(char*)"(null-error)";
	} else {
		title = strdup(s);
	}
	
	// Récupération de l'ID
	if (json_object_has_member(jso, "id")) {
		id=json_object_get_int_member (jso, "id");
	} else {
		printf("%s() Runtime : missing 'title' fields in json stream\n");
		id=-1;
	}	

	// Récupération des secrets
	secrets=NULL;
	GList *gl = json_array_get_elements (json_object_get_array_member (jso, "secrets"));
	for ( ; gl != NULL; gl=gl->next) {
		//secrets = g_list_append(secrets, new t_secret_item(json_node_get_object ((JsonNode*)gl->data), this));
		secrets = tdll_append(secrets, new t_secret_item(json_node_get_object ((JsonNode*)gl->data), this));
	}

	// Récupération des sous dossiers
	sub_folders=NULL;
	gl = json_array_get_elements (json_object_get_array_member (jso, "sub_folders"));
	for ( ; gl != NULL; gl=gl->next) {
		//sub_folders = g_list_append(sub_folders, new t_secret_folder(json_node_get_object ((JsonNode*)gl->data), this, db));
		sub_folders = tdll_append(sub_folders, new t_secret_folder(json_node_get_object ((JsonNode*)gl->data), this, db));
	}
}
#endif
#ifdef  MPM_JANSSON
t_secret_folder::t_secret_folder(json_t *jso, t_secret_folder* parent_, t_database *db_) {
	parent = parent_;
	db=db_;

	// Récupération du titre
	json_t *jst = json_object_get(jso, "title");
	const char *s = json_string_value(jst);
	if ((jst == NULL) || (s == NULL)) {
		printf("%s() Runtime : missing 'title' fields in json stream\n", __func__);
		title =(char*)"(null-error)";
	} else {
		title = strdup(s);		
	}
		
	// Récupération de l'ID
	json_t *jsid = json_object_get(jso, "id");
	if (jsid) {
		id=json_integer_value(jsid);
	} else {
		printf("%s() Runtime : missing 'title' fields in json stream\n", __func__);
		id=-1;
	}	
	
	// Récupération des secrets
	secrets=NULL;
	json_t *jssa = json_object_get(jso, "secrets");
	int n = json_array_size(jssa);
	for (int i=0; i<n; i++) {
		json_t *jss = json_array_get(jssa, i);
		secrets = tdll_append(secrets, new t_secret_item(jss, this));
	}
	
	// Récupération des sous dossiers
	sub_folders=NULL;
	json_t *jssfa = json_object_get(jso, "sub_folders");
	n = json_array_size(jssfa);
	for (int i=0; i<n; i++) {
		json_t *jssf = json_array_get(jssfa, i);
		sub_folders = tdll_append(sub_folders, new t_secret_folder(jssf, this, db));
	}	
}
#endif


t_secret_folder::~t_secret_folder() {
	/*GList*/ tdllist* gl;
	
	// Libère les sous dossiers
	for (gl=sub_folders; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			delete (t_secret_folder*)gl->data;
		} else {
			abort();
		}
	}
	
	// Libère les secrets
	for (gl=secrets; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			delete (t_secret_item*)gl->data;
		} else {
			abort();
		}	
	}

	// Libère le titre
	if (title != NULL) {
		memset(title, 0, sizeof(title));
		free(title);
	} else {
		abort();
	}
}

#ifdef MPM_GLIB_JSON
JsonNode *t_secret_folder::save() {
	JsonObject *object = json_object_new();
	json_object_set_member (object, "title",      json_node_init_string (json_node_alloc (), title));	
	json_object_set_member (object, "id",         json_node_init_int (json_node_alloc (), id));	
	
	

	// Traitement de la liste des secrets
	JsonArray* json_array = json_array_new();
	for (/*GList*/ tdllist* gl = secrets; gl != NULL; gl=gl->next) {
		json_array_add_element(json_array, ((t_secret_item*)gl->data)->save());
	}
	json_object_set_member (object, "secrets",     json_node_init_array (json_node_alloc (), json_array));	

	// Traitement de la liste des sous dossiers (récursif)
	json_array = json_array_new();
	for (tdllist* gl = sub_folders; gl != NULL; gl=gl->next) {
		json_array_add_element(json_array, ((t_secret_folder*)gl->data)->save());
	}
	json_object_set_member (object, "sub_folders",     json_node_init_array (json_node_alloc (), json_array));	


	return json_node_init_object (json_node_alloc (), object);
}

#endif
#ifdef  MPM_JANSSON
json_t *t_secret_folder::save() {
	json_t *jso = json_object();
	if (jso == NULL) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
		#endif
		return NULL;
	}
	
	json_object_set(jso, "title", json_string (title));
	json_object_set(jso, "id",    json_integer(id));
	
	// Traitement de la liste des secrets
	json_t *jssa = json_array();
	for (tdllist* gl = secrets; gl != NULL; gl=gl->next) {
		json_array_append(jssa, ((t_secret_item*)gl->data)->save());
	}
	json_object_set (jso, "secrets", jssa);	

	// Traitement de la liste des sous dossiers (récursif)
	json_t *jssfa = json_array();
	for (tdllist* gl = sub_folders; gl != NULL; gl=gl->next) {
		json_array_append(jssfa, ((t_secret_folder*)gl->data)->save());
	}
	json_object_set (jso, "sub_folders", jssfa);	
	
	return jso;
}
#endif



/*GList*/ tdllist *t_secret_folder::get_sub_folders() {
	return sub_folders;
}

/*GList*/ tdllist *t_secret_folder::get_secrets() {
	return secrets;
}

uint32_t t_secret_folder::get_id() {
	return id;
}

char *t_secret_folder::get_title() {
	return title;
}

void t_secret_folder::set_title(char* title_){
	if (title) {
		memset(title, 0, sizeof(title));
		free(title);	
	}
	title=strdup(title_);
	db->set_changed(MPM_CHANGED_SECRET);
}


/** 
 * \brief renvoie le chemein complet du dossier
 * \todo le faire vraiment, car pour le moment ça ne renvoie que le titre du dossier courant, sans le chemin parent
 */
char *t_secret_folder::get_title_path() {
	return title;
}


t_secret_folder *t_secret_folder::get_parent_folder() {
	return parent;
}

t_secret_folder *t_secret_folder::get_sub_folder_by_id(int id) {
	/*GList*/ tdllist* gl;
	for (gl=sub_folders; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			if ( ((t_secret_folder*)gl->data)->get_id() == id ) return (t_secret_folder*)gl->data;
		} else {
			abort();
		}
	}
	return NULL;
}


t_secret_item* t_secret_folder::get_secret_by_id(int id) {
	/*GList*/ tdllist* gl;
	for (gl=secrets; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			if ( ((t_secret_item*)gl->data)->get_id() == id ) return (t_secret_item*)gl->data;
		} else {
			abort();
		}
	}
	return NULL;
}


/**
 * \brief Insère un nouveau sous-dossier dans ce dossier
 */
void t_secret_folder::add_sub_folder(t_secret_folder* nf) {
	//sub_folders = g_list_append(sub_folders, nf);
	sub_folders = tdll_append(sub_folders, nf);
	db->set_changed(MPM_CHANGED_SECRET);
}


/**
 * \brief Insère un nouveau secret dans ce dossier
 */
void t_secret_folder::add_secret_item(t_secret_item *secret){
	//secrets=g_list_append(secrets, secret);
	secrets=tdll_append(secrets, secret);
	db->set_changed(MPM_CHANGED_SECRET);
}

/**
 * \brief Supprime un secret donné par son ID
 */
void t_secret_folder::delete_secret_item(int id){
	//printf("%s() ligne %d du fichier %s : fonction pas implémentée\n", __func__, __LINE__, __FILE__);
	
	/*GList*/ tdllist* gl;
	for (gl=secrets; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			if ( ((t_secret_item*)gl->data)->get_id() == id ) {
				delete (t_secret_item*)gl->data;
				gl->data=NULL;
				//secrets = g_list_delete_link (secrets, gl);
				secrets = tdll_delete_link(secrets, gl);
				return;
			}
		} else {
			abort();
		}
	}
	db->set_changed(MPM_CHANGED_SECRET);
	return;	
}


/**
 * \brief Supprime les secrets et sous dossier du dossier (récursivement)
 * \note Appelle les destructeurs correspondant, sauf pour soi-même
 */
void t_secret_folder::delete_all() {
	/*GList*/ tdllist* gl;
	
	// Supprime d'abord les secrets
	for (gl=secrets; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			delete (t_secret_item*)gl->data;
			gl->data=NULL;
			//secrets = g_list_delete_link (secrets, gl);
			secrets = tdll_delete_link(secrets, gl);
		} else {
			abort();
		}
	}
	//g_list_free(secrets);
	tdll_free(secrets);
	secrets=NULL;
	
	// Puis les sous dossiers
	for(gl=sub_folders; gl; gl=gl->next) {
		if (gl->data != NULL) {
			((t_secret_folder*)gl->data)->delete_all();
			delete (t_secret_folder*)gl->data;
			gl->data=NULL;
		} else {
			abort();
		}
	}
	//g_list_free(sub_folders);
	tdll_free(sub_folders);
	sub_folders=NULL;
	db->set_changed(MPM_CHANGED_SECRET);
	return;	
}


void t_secret_folder::delete_sub_folder(int id) {
	//printf("%s() ligne %d du fichier %s : fonction pas implémentée\n", __func__, __LINE__, __FILE__);
	
	t_secret_folder *sf = get_sub_folder_by_id(id);
	
	if (sf != NULL) {
		//sub_folders=g_list_remove(sub_folders, sf);
		sub_folders=tdll_remove(sub_folders, sf);
		sf->delete_all();
		delete sf;
	}
	db->set_changed(MPM_CHANGED_SECRET);
}


/**
 * \brief Indique si un ID de dossier/secret est disponible
 * \note Les ID des dossiers et des secrets sont pris dans le même espace, et sont uniques, mais recyclés. A chaque nouvel objet, on cherche l'ID le plus petit
 */
bool t_secret_folder::is_id_free(uint32_t id_) {
	if (id == id_) return false;

	/*GList*/ tdllist* gl;

	// Parcours les sous dossiers
	for (gl=sub_folders; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			if ( ((t_secret_folder*)gl->data)->is_id_free(id_) == false ) return false;

		} else {
			abort();
		}
	}

	// parcours les secret items
	for (gl=secrets; gl!=NULL; gl=gl->next) {
		if (gl->data != NULL) {
			if ( ((t_secret_item*)gl->data)->get_id()== id_ ) return false;
		} else {
			abort();
		}	
	}	
	return true;
}


/**
 * \brief Renvoie la chaine à utiliser comme prompt
 * \todo Gérer la troncature pour que ce soit un prompt pas trop long. Risque de buffer overflow
 */
char *t_secret_folder::prompt() {
	static char prompt[CPARSER_MAX_PROMPT];
	memset(prompt, 0, sizeof(prompt));
	
	if (db->is_changed()) {
		strncat(prompt, "*", CPARSER_MAX_PROMPT);
	}
	
	strcat(prompt, title);
	strcat(prompt, "(sec)");

	switch (db->status) {
		case MPM_LEVEL_COMMON :  /* Base ouverte, on a le quorum "common" */
			strncat(prompt, "> ", CPARSER_MAX_PROMPT);
			break;

		case MPM_LEVEL_SECRET :		
			strncat(prompt, "# ", CPARSER_MAX_PROMPT);
			break;
			
		case MPM_LEVEL_INIT : /* Base vide pas encore initialisée */
		case MPM_LEVEL_NONE : /* Base non ouverte, ne peut pas être encore différenciée d'une suite d'octets aléatoires */
		case MPM_LEVEL_FIRST :  /* Au moins un utilisateur a été reconnu, mais pas encore de quorum "common" */
		default:
			printf("runtime error\n");
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() %s:%d runtime error\n", __func__, __FILE__, __LINE__);
			#endif
			break;
	}
	return prompt;
}

bool t_secret_folder::is_empty() {
	if (secrets) return false;
	if (sub_folders) return false;
	return true;
}

t_database *t_secret_folder::get_db() {
	return db;
}
