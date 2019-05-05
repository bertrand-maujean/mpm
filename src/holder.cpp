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



/** \class t_holder
 * Classe "holder"
 * 
 * \note Façon de créer un objet de type holder
 * - Création d'une nouvelle holder
 *    - appel du constructeur pour créer une holder à partir de son nickname. Créé en chunk_status=HOLDER_CHUNK_STATUS_NONE (=absent sur disque)
 *    - enitèrement qualifié au départ, mais le chunk n'est pas initialisé. Il le sera à l'appel à la méthode save_chunk()
 * - Ouverture précoce, c'est à dire try avant l'ouverture de la base common
 *    - création par le constructeur à partir d'un nickname, file_index, pkey, chunk déchiffré. chunk_status=HOLDER_CHUNK_STATUS_OPEN
 *    - ensuite, lorsque la base common sera ouverte, on réappelle complete_ouverture() 
 *      pour intégrer les informations qui sont dans la base common mais pas dans le cunk holder
 * - Ouverture tardive, c'est à dire try après que la base common soit ouverte
 *    - Cas de la holder qui permet l'ouverture du niveau secret
 *    - La holder a été créée avant le try, à l'ouverture de la base common. Mais alors on a fixé chunk_status=HOLDER_CHUNK_STATUS_CLOSED	
 *    - L'appel à try_tardif() permet de déchiffrer le chunk, et de passer en chunk_status=HOLDER_CHUNK_STATUS_OPEN
 */
  
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "holder.h"
#include "crypto_wrapper.h"




/** Constructeur
 *  \brief Ppour création d'une holder nouvelle qui n'existait pas avant, à partir d'un nouveau nickname
 *  \param[in]   nn        Le nickname de la holder à créer
 *  \param[in]   db_       Lien vers la base, car on en a besoin par moment
 *  \note 
 *  - Chunk_status=HOLDER_CHUNK_STATUS_NONE car le chunk n'est pas écrit sur disque
 *  - Chunk initialisé aléatoirement, parts générées en invoquant le sss de la db_
 */
t_holder::t_holder(char *nn, t_database *db_) {
	nickname=(char*)malloc(strlen(nn)+1);
	strcpy(nickname, nn);
	
	email=NULL;
	id_holder=0;
	password_set=false;
	
	random_bytes(parts, CHUNK_MAX_PARTS*32);     // Pour rendre notre chiffrement plus robuste, on n'encoderait surtout pas des zéros !
	random_bytes(xparts, CHUNK_MAX_PARTS*8);     // Donc on remplit avec de l'aléa tant qu'on a pas de données plus importantes à y mettre
	random_bytes(chunk, CHUNK_HOLDER_SIZE);
	
	db = db_;
	chunk_status=HOLDER_CHUNK_STATUS_NONE;       // Ce holder n'a pas encore de chunk dans le fichier sur disque
	random_bytes(salt1, 32);                     // Les sels pour le chunk sur disque
	random_bytes(salt2, 32);
	id_holder = db->get_next_id_holder();        // Récupère un ID de holder
	file_index=-1;                               // sera recalculé pendant le save()
	
	common_nb_parts=secret_nb_parts=1;           // Les holders sont dotés d'une part de chaque à la création
	emet_parts();                                // Emission des parts
}

/** Constructeur
 *  \brief Pour création d'une holder d'après un chunk lu avant ouverture de la base common
 *  \param[in]   nn         Le nickname de la holder à créer
 *  \param[in]   db_        Lien vers la base, car on en a besoin par moment
 *  \param[in]   chunk      Le chunk lu et déchiffré
 *  \param[in]   file_index Transmis par le try() et à conserver
 *  \param[in]   pkey       Transmis par le try() et à conserver. On ne pourrait pas le recalculer car on ne conserve pas le MdP plus que ça
 *  \note 
 *  - Chunk_status=HOLDER_CHUNK_STATUS_OPEN car le chunk est présent sur disque, et déchiffré
 */
t_holder::t_holder(char *nn, t_database *db_, t_chunk_holder *chunk_, int file_index_, unsigned char *pkey_) {
	nickname=strdup(nn);

	password_set=true;
	memcpy(chunk, chunk_, CHUNK_HOLDER_SIZE);
	email=NULL;
	id_holder=((t_chunk_holder*)chunk)->id_holder;
	memcpy(parts,  ((t_chunk_holder*)chunk)->parts,  CHUNK_MAX_PARTS*32);
	memcpy(xparts, ((t_chunk_holder*)chunk)->xparts, CHUNK_MAX_PARTS*8);	
	db = db_;

	memcpy(salt1, ((t_chunk_holder*)chunk)->salt1, 32);
	memcpy(salt2, ((t_chunk_holder*)chunk)->salt2, 32);
	memcpy(hash,  ((t_chunk_holder*)chunk)->hash,  32);
	memcpy(pkey,  pkey_, 32);
	common_nb_parts=((t_chunk_holder*)chunk)->common_nb_parts;
	secret_nb_parts=((t_chunk_holder*)chunk)->secret_nb_parts;
	
	//common_treshold = ((t_chunk_holder*)chunk)->common_treshold; abandon de l'idée de cloner ces données, elles doivent rester dans l'image du chunk déchiffré
	//secret_treshold = ((t_chunk_holder*)chunk)->secret_treshold;
	
	file_index=file_index_;
	chunk_status=HOLDER_CHUNK_STATUS_OPEN;
}



/** Constructeur
 *  \brief Pour création d'une holder d'après la conf json, au moment de l'ouverture de la base common
 *  \param[in]   db_        Lien vers la base, car on en a besoin par moment
 *  \param[in]   jso        L'objet json contenant les informations
 *  \note
 *  - Les derniers constructeurs de holders pour ouvrir un fichier sont appelés ensemble à ce moment. Toutes les holders du fichier sont alors chargées.
 *  - Appelé uniquement pour les holders qui n'ont pas été chargées avant. Pour les holders qui ont été chargées avant l'ouverture du niveau common, 
 *    l'objet holder a déjà été créé, on appelera juste complete_ouverture()
 *  - Chunk_status=HOLDER_CHUNK_STATUS_CLOSE car le chunk est présent sur disque, mais pas déchiffré
 *  - sera déchiffré par un appel à try_tardif()
 */
 
 
#ifdef MPM_GLIB_JSON
t_holder::t_holder(t_database *db_, JsonObject *jso) {
#endif
#ifdef  MPM_JANSSON
t_holder::t_holder(t_database *db_, json_t *jso) {
#endif

	#ifdef MPM_GLIB_JSON
	char *nn = (char*)json_object_get_string_member (jso, "nickname");
	nickname = strdup(nn);

	if (json_object_has_member(jso, "email")) {
		email=strdup((char*)json_object_get_string_member (jso, "email"));
	} else {
		#ifdef DEBUG
		//debug_printf(0, (char*)"%s() %s n'a pas d'email dans le json\n", __func__, nickname);
		#endif
		email=NULL;
	}

	db=db_;
	id_holder       = json_object_get_int_member(jso, "id_holder");
	file_index      = json_object_get_int_member(jso, "file_index");
	common_nb_parts = json_object_get_int_member(jso, "common_nb_parts");
	secret_nb_parts = json_object_get_int_member(jso, "secret_nb_parts");
	#endif /* GLIB_JSON */


	#ifdef  MPM_JANSSON
	json_t *jsnn = json_object_get(jso, "nickname");
	assert(jsnn != NULL);
	nickname = strdup(json_string_value(jsnn));
	
	json_t *jsem = json_object_get(jso, "email");
	if (jsem) {
		email=strdup((char*)json_string_value (jsem));
	} else {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s n'a pas d'email dans le json\n", __func__, nickname);
		#endif
		email=NULL;
	}	
	db=db_;
	id_holder       = json_integer_value( json_object_get(jso, "id_holder"));
	file_index      = json_integer_value( json_object_get(jso, "file_index"));
	common_nb_parts = json_integer_value( json_object_get(jso, "common_nb_parts"));
	secret_nb_parts = json_integer_value( json_object_get(jso, "secret_nb_parts"));	
	#endif /* MPM_JANSSON */
	
	//common_treshold = db->common_treshold; abandon de l'idée de cloner ces données, elles doivent rester dans l'image du chunk déchiffré
	//secret_treshold = db->secret_treshold;	
	
	password_set=true;
	chunk_status=HOLDER_CHUNK_STATUS_CLOSED;

	char *fn = db_->filename;
	FILE *f = fopen(fn,"r+b");
	if (f == NULL) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur à l'ouverture du fichier %s\n", __func__, fn);
		#endif
		printf("Erreur à la lecture du fichier\n");
		return;
	}
	fseek(f, file_index*CHUNK_HOLDER_SIZE , SEEK_SET);
	int lus=fread(chunk, 1, CHUNK_HOLDER_SIZE, f);
	fclose(f);
	if (lus != CHUNK_HOLDER_SIZE) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur sur le nombre d'octets lus\n", __func__, nickname);
		#endif	
	}
	#ifdef DEBUG
	debug_printf(0, (char*)"%s() %s holder closed lus=%d file_index=%d\n", __func__, nickname, lus, file_index);
	debug_printf(0, (char*)"%s() chunk=%lx partie chiffrée=%lx\n", (char*)__func__, *(uint64_t*) chunk, *(uint64_t*) (chunk+CHUNK_HOLDER_AES_OFFSET));
	#endif
}


/** 
 *  \brief Complète les informations d'une holder qui a participé à l'ouverture common, une fois que la la base common est disponible
 *  \param[in]   jso        L'objet json contenant les informations
 *  \note
 *  - Contrôle de cohérence des informations disponibles à la fois dans le chunk et dans la base common
 *  - chargement des infos supplémentaires : email
 *  - chunk_status inchangé, il est déjà censé re à HOLDER_CHUNK_STATUS_OPEN
 */
#ifdef MPM_GLIB_JSON
void t_holder::complete_ouverture(JsonObject *jso) {
	// Vérification de cohérence des informations stockées également dans le chunk holder
	if (json_object_get_int_member (jso, "common_nb_parts") != common_nb_parts) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence common %d != %d pour %s\n", __func__, json_object_get_int_member (jso, "common_nb_parts"), common_nb_parts, nickname);
		#endif	
	}
	if (json_object_get_int_member (jso, "secret_nb_parts") != secret_nb_parts) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence secret %d != %d pour %s\n", __func__, json_object_get_int_member (jso, "secret_nb_parts"), secret_nb_parts, nickname);
		#endif	
	}
	if (json_object_get_int_member (jso, "id_holder") != id_holder) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence id_holder %d != %d pour %s\n", __func__, json_object_get_int_member (jso, "id_holder"), secret_nb_parts, nickname);
		#endif	
	}	
	
	
	// Complète email
	if (json_object_has_member(jso, "email")) {
		email=strdup((char*)json_object_get_string_member (jso, "email"));
	} else {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s n'a pas d'email dans le json\n", __func__, nickname);
		#endif
	}	
	
	
	// Vérification cohérence
	if (chunk_status != HOLDER_CHUNK_STATUS_OPEN) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s incohérence, chunk_status!=HOLDER_CHUNK_STATUS_OPEN\n", __func__, nickname);
		#endif	
	}
	
	#ifdef DEBUG
	debug_printf(0, (char*)"%s() %s holder complété\n", __func__, nickname);
	#endif
}
#endif

#ifdef  MPM_JANSSON
void t_holder::complete_ouverture(json_t *jso) {
	if (!json_is_object(jso)) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() erreur : n'est pas un object\n", __func__);
		#endif
		return;
	}

	if (json_integer_value(json_object_get(jso, "common_nb_parts")) != common_nb_parts) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence common %d\n", __func__);
		#endif	
	}
	if (json_integer_value(json_object_get(jso, "secret_nb_parts")) != secret_nb_parts) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence secret\n", __func__);
		#endif	
	}
	if (json_integer_value(json_object_get(jso, "id_holder")) != id_holder) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() incohérence id_holder\n", __func__);
		#endif	
	}	
	
	// Complète email
	if (json_t *jsm = json_object_get(jso, "email")) {
		email=strdup((char*)json_string_value(jsm));
	} else {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s n'a pas d'email dans le json\n", __func__, nickname);
		#endif
	}	
		
	// Vérification cohérence
	if (chunk_status != HOLDER_CHUNK_STATUS_OPEN) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s incohérence, chunk_status!=HOLDER_CHUNK_STATUS_OPEN\n", __func__, nickname);
		#endif	
	}
	#ifdef DEBUG
	debug_printf(0, (char*)"%s() %s holder complété\n", __func__, nickname);
	#endif
}
#endif


/*
 *  \brief Génère un prompt dans un contexte d'édition de holder
 *  \note
 *  - Généré dans un emplacement statique
 *  \return pointeur vers le prompt, emplacement statique 
 *  \todo Gérer correctement la taille de buffer (nb : strncat ne limite que la taille ajoutée, pas la taille totale)
 *  \todo Que le prompt indique l'état du chunk
 */
/* 
char *t_holder::prompt() {
	static char prompt[CPARSER_MAX_PROMPT];
	memset(prompt, 0, sizeof(prompt));

	strncat(prompt, nickname, CPARSER_MAX_PROMPT);
	strncat(prompt, "(hld)> ", CPARSER_MAX_PROMPT);
	return prompt;
}
*/

/** 
 *  \brief Termine l'ouvture d'une holder qui n'a pas participer à l'ouverture de la base common. Le try a été fait après
 *  \param[in]   password        Le MdP tranmis par le dialogue try
 *  \note
 *  - Déchiffrement du chunk qui est alors déjà chargé en mémoire. Plus d'accès au fichier sur disque
 *  - chunk_status passe de HOLDER_CHUNK_STATUS_CLOSED à HOLDER_CHUNK_STATUS_OPEN
 *  \return utilise les constantes MPM_TRY_* comme t_database::try_nickname() 
 */
int t_holder::try_tardif(char *password) {
	t_chunk_holder *c;
	unsigned char hash_calcule[32];
	unsigned char pkey_calculee[32];
	
	if (chunk_status != HOLDER_CHUNK_STATUS_CLOSED) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() Erreur pour '%s' - n'était pas en HOLDER_CHUNK_STATUS_CLOSED\n", (char*)__func__, nickname);
		#endif	
		return MPM_TRY_ALREADY_OPENED;
	}

	#ifdef DEBUG
	debug_printf(0,(char*)"%s() chunk=%lx partie chiffrée=%lx\n", (char*)__func__, *(uint64_t*) chunk, *(uint64_t*) (chunk+CHUNK_HOLDER_AES_OFFSET));
	#endif

	c = (t_chunk_holder *)chunk;
	//t_chunk_holder * c2=(t_chunk_holder *)alloca(CHUNK_HOLDER_SIZE);

	//cw_database_find_chunk_holder_hash(nickname, (unsigned char*)c->salt1, password, (unsigned char*)hash_calcule);
	cw_sha256_iterated_mix1(hash_calcule, nickname, c->salt1, password);
	if (memcmp(c->hash,hash_calcule,32 ) ==0) {

		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s password ok\n", __func__, nickname);
		#endif
		//cw_database_find_chunk_holder_pkey(nickname, (unsigned char*)c->salt2, password, (unsigned char*)pkey_calculee);
		cw_sha256_iterated_mix1(pkey_calculee, nickname, c->salt2, password);
		//cw_holder_dechiffre_chunk((unsigned char*)c2, (unsigned char*)c, (unsigned char*)pkey_calculee, c->salt1);
		cw_aes_cbc((unsigned char*)c + CHUNK_HOLDER_AES_OFFSET, CHUNK_HOLDER_AES_SIZE, pkey_calculee, c->salt1, 0);
		if (c->magic == CHUNK_HOLDER_MAGIC) {
			//memcpy((unsigned char*)c + CHUNK_HOLDER_AES_OFFSET, (unsigned char*)c2 + CHUNK_HOLDER_AES_OFFSET, CHUNK_HOLDER_AES_SIZE);
				// Rappel : la fonction cw_... ne traite pas les octets non chiffrés
			memcpy(pkey,   pkey_calculee, 32);
			memcpy(salt1,  c->salt1,      32);
			memcpy(salt2,  c->salt2,      32);
			memcpy(hash,   c->hash,       32);
			memcpy(parts,  c->parts,      CHUNK_MAX_PARTS*32);
			memcpy(xparts, c->xparts,     CHUNK_MAX_PARTS*sizeof(xparts[0]));
			chunk_status = HOLDER_CHUNK_STATUS_OPEN;
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() %s magic ok pkey=%lx\n", __func__, nickname, *(uint64_t*)pkey);
			debug_printf(0, (char*)"%s() %s part[0]=%lx part[7]=%lx\n", __func__, nickname, *(uint64_t*)&parts[0], *(uint64_t*)&parts[7*32]);
			#endif
			return MPM_TRY_OK;
		} else {
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() %s %s magic invalide\n", __func__, nickname, password);
			#endif
			return MPM_TRY_NOT_FOUND;			
		}
	} else {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s password erroné\n", __func__, nickname);
		#endif	
		return MPM_TRY_NOT_FOUND;
	}
}



/** destructeur */
t_holder::~t_holder() {
	db->set_changed(MPM_CHANGED_HOLDER);
	if (nickname) free(nickname);
	if (email) free(email);
}

/** 
 *  \brief Teste le nickname
 *  \param[in]   nn Le nickname à comparer à celui de la holder en question
 *  \return 0=ce n'est pas lui, 1=nicknames égaux
 */
int t_holder::is_nickname(char *nn) {
	if (strcmp(nn, nickname) == 0) return 1;
	return 0;
}

/** 
 *  \brief Renvoie le pointeur sur la chaine contenant l'email
 *  \return le pointeur
 */
char *t_holder::get_email() {
	return email;
}

/** 
 *  \brief Renvoie l'ID de holder
 *  \return l'ID
 */
int t_holder::get_id_holder() {
	return id_holder;
}

/** 
 *  \brief Fixe l'email
 *  \note 
 *  - Eventuellement à NULL si on donne comme argument une chaine vide
 *  - L'email stocké dans l'objet sera alloué par malloc()
 *  - si l'email n'était pas NULL avant : alors on suppose qu'il était déjà fixé, on doit le remplacer. L'ancien est libéré par free()
 */
void t_holder::set_email(char *em) {
	int l;
	if (email) free(email);

	if (em) {
		l=strlen(em);
		if (l>0) {
			email=(char*)malloc(l+1);
			strcpy(email, em);
			return;
		}
	}
	db->set_changed(MPM_CHANGED_HOLDER);
	email=NULL;
}

/** 
 *  \brief Renvoie le nombre de parts sont dispose cette holder, pour le niveau common
 *  \return le nombre
 */
int t_holder::get_nb_common() {
	return common_nb_parts;
}


/** 
 *  \brief Modifie le nombre de parts portées par cette holder, pour le niveau common
 *  \note 
 *  - Le nombre de part total ne doit pas dépasser CHUNK_MAX_PARTS
 *  - invoque le sss de la db
 */
bool t_holder::set_nb_common(int n) {
	if ( (n+secret_nb_parts < CHUNK_MAX_PARTS) && ( (chunk_status == HOLDER_CHUNK_STATUS_OPEN) || (chunk_status == HOLDER_CHUNK_STATUS_NONE) ) ) {
		common_nb_parts=n;
		emet_parts();	
		return true;
	}
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() echec pour cause de nb parts incohérent ou chunk pas ouvert\n", __func__);
	#endif
	return false;
}

/** 
 *  \brief Renvoie le nombre de parts sont dispose cette holder, pour le niveau secret
 *  \return le nombre
 */
int t_holder::get_nb_secret() {
	return secret_nb_parts;
}

/** 
 *  \brief Modifie le nombre de parts portées par cette holder, pour le niveau secret
 *  \note 
 *  - Le nombre de part total ne doit pas dépasser CHUNK_MAX_PARTS
 *  - invoque le sss de la db
 */
bool t_holder::set_nb_secret(int n) {
	if ( (n+common_nb_parts < CHUNK_MAX_PARTS) && ( (chunk_status == HOLDER_CHUNK_STATUS_OPEN) || (chunk_status == HOLDER_CHUNK_STATUS_NONE) ) ) {
		secret_nb_parts=n;
		emet_parts();	
		return true;
	}
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() echec pour cause de nb parts incohérent ou chunk pas ouvert\n", __func__);
	#endif
	return false;
}



/** 
 *  \brief Emet ou ré-emet les parts, pour les deux niveaux common et secret
 *  \note 
 *  - Erreur fatal si nb de parts incohérent
 *  - Les parts émises sont mises dans la classe, mais dans dans le chunk binaire. ceci sera fait par la méthode save()
 *  - invoqué par le constructeur de création d'un nouveau holder, et par les set_nb_XXX, lors des changements de nombre de parts
 *  - Du coup, lors des changements de nombres de parts, on en profite pour ré-emettre toutes les parts
 */
void t_holder::emet_parts() {
	/// Cinq vérification fatales pour être sûr
	if (common_nb_parts+secret_nb_parts > CHUNK_MAX_PARTS) { // Limite que le nombre total de parts ne doit pas dépasser
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() quantité de parts incorrecte\n", __func__);
		#endif
		abort();
	}
	
	if ( (chunk_status != HOLDER_CHUNK_STATUS_OPEN) && (chunk_status != HOLDER_CHUNK_STATUS_NONE) ) { // Limite que le nombre total de parts ne doit pas dépasser
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() émission de part impossible, chunk pas ouvert pour %s\n", __func__, nickname);
		#endif
		abort();
	}
	if (db->sss_common ==NULL) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() sss_common == NULL\n", __func__);
		#endif
		fprintf(stderr, "runtime error\n");
		abort();
	} 
	if (db->sss_secret ==NULL) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() sss_secret == NULL\n", __func__);
		#endif
		fprintf(stderr, "runtime error\n");
		abort();
	} 
	if ((chunk_status != HOLDER_CHUNK_STATUS_NONE) && (chunk_status != HOLDER_CHUNK_STATUS_OPEN)) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() Appel pour un holder qui n'est pas en état OPEN ou NONE\n", __func__);
		#endif
		fprintf(stderr, "runtime error\n");
		abort();
	}
	
	// Remet ou à une valeur aléatoire. On va écraser les parts effectivement utilisées, 
	// et laisser ce bruit aléatoire renouvelé sur les parties non utililsées
	random_bytes(parts, CHUNK_MAX_PARTS*32);
	random_bytes( xparts, CHUNK_MAX_PARTS*sizeof(uint64_t));	

	unsigned char* part_temp = (unsigned char*)alloca( 8* db->sss_common->size);

		// Emission des parts 'common'
	for (int i=0; i< common_nb_parts; i++) {
		uint64_t x;
		random_bytes(&x, sizeof(x));
		x=0;
		x &= 0xfffffffffff80000;
		x |= id_holder;
		x |= (i<<16);
		
		lsss_get_part(db->sss_common, part_temp, x);
		memcpy(&parts[32*i], part_temp, 32);
		
		xparts[i] =x;
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() %s generation de part pour le niveau 'common' x=%lx y=%lx..%lx\n", __func__, nickname, xparts[i], *(uint64_t*) &parts[i*32], *(uint64_t*) &parts[i*32+24] );
		#endif	
	}


	// Emission des parts 'secret'
	for (int i=7; i>= (CHUNK_MAX_PARTS-secret_nb_parts); i--) {
		uint64_t x;
		random_bytes(&x, sizeof(x));
		x=0;
		x &= 0xfffffffffff80000;
		x |= id_holder;
		x |= (i<<16);
		lsss_get_part(db->sss_secret, part_temp, x);
		memcpy(&parts[32*i], part_temp, 32);
		xparts[i] =x;
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() %s generation de part pour le niveau 'secret' x=%lx y=%lx..%lx\n", __func__, nickname, xparts[i], *(uint64_t*) &parts[i*32], *(uint64_t*) &parts[i*32+24] );
		#endif
	}
	// Génération du xpart pour la première part, génération de la part
	// Le xpart est composé ainsi :
	// bits 0..15 = holder_id
	// bits 16..18 = l'index de la part dans le chunk (0 à 7, 3 bits)
	// bits 19..64 = aléatoire
	// Ainsi, on est sûr de ne pas distribuer 2 fois la même part

	db->set_changed(MPM_CHANGED_HOLDER);
}



/** 
 *  \brief Change le mot de passe
 *  \note 
 *  - Cela revient à recalculer la pkey et le hash
 */
void t_holder::set_password(char *mdp) {
	if ((chunk_status != HOLDER_CHUNK_STATUS_OPEN) && (chunk_status != HOLDER_CHUNK_STATUS_NONE)) {
		// NB : on ne peut changer le MdP que des holders ayant ouvert leur chunk, car sinon le chunk ne sera pas réencodé
		#ifdef DEBUG 
		debug_printf(0, (char*)"%s() Erreur le chunk holder n'est pas en état de changer le MdP\n",(char*)__func__);
		#endif
	} else {
		cw_sha256_iterated_mix1(pkey, nickname, salt2, mdp);
		cw_sha256_iterated_mix1(hash, nickname, salt1, mdp);
	}
	password_set = true;
	db->set_changed(MPM_CHANGED_HOLDER);
}

/** 
 *  \brief Teste le MdP d'un holder par rapport à un MdP proposé
 *  \note 
 *  - Ce n'est pas cette fonction qui est utilisé pour 'try'
 *  - Cette focntione est utilisée pour le dialogue de changement du MdP
 *  \todo Faire le contenu de cette fonction...
 */
bool t_holder::test_password(char *mdp) {
	unsigned char hash_calcule[32];

	debug_printf(0, (char*)"%s() Il faudra implémenter le contenu de cette fonction\n",(char*)__func__);
	if ((chunk_status != HOLDER_CHUNK_STATUS_OPEN) && (chunk_status != HOLDER_CHUNK_STATUS_NONE)) {
		#ifdef DEBUG 
		debug_printf(0, (char*)"%s() Erreur le chunk holder n'est pas en état de tester le MdP\n",(char*)__func__);
		#endif
		return false;
	} else {
		cw_sha256_iterated_mix1(hash_calcule, nickname, salt1, mdp);
	}
	return (memcmp(hash_calcule,hash,32) ==0); 
}



/** 
 *  \brief Ecrit le chunk dans le fichier
 *  \param[in] fichier Le fichier dans lequel on écrit
 *  \note 
 *  - invoqué par t_database::save()
 *  - Fait le chiffrement
 *  - Le "file_index" a été fixé par le t_database::save()
 */
void t_holder::save_chunk(FILE *fichier) {
	t_chunk_holder *p;
	if (chunk_status == HOLDER_CHUNK_STATUS_CLOSED) { // Cas d'une holder pas 'ouverte'. Le chunk n'a pas été déchiffré, il est réécrit tel quel
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() écriture chunk '%s' état closed\n", (char*)__func__, nickname);
		debug_printf(0,(char*)"%s() chunk=%lx partie chiffrée=%lx\n", (char*)__func__, *(uint64_t*) chunk, *(uint64_t*) (chunk+CHUNK_HOLDER_AES_OFFSET));
		#endif	
	
		fwrite(chunk, CHUNK_HOLDER_SIZE, 1, fichier);
	} else if (chunk_status == HOLDER_CHUNK_STATUS_NONE || chunk_status == HOLDER_CHUNK_STATUS_OPEN) { 
		p=(t_chunk_holder *)chunk;

		// Prépare tout ce qui est avant la partie chiffrée
		memcpy(p->salt1, salt1, 32);
		memcpy(p->salt2, salt2, 32);
		memcpy(p->hash,  hash,  32);

		// Prépare le contenu de la partie chiffrée
		memcpy(&p->xparts[0], &xparts[0], sizeof(&xparts[0])*CHUNK_MAX_PARTS);
		memcpy(&p->parts[0],  &parts[0], 32*CHUNK_MAX_PARTS);

		p->common_treshold=db->common_treshold; 
		p->common_nb_parts=common_nb_parts; 
		p->secret_treshold=db->secret_treshold;
		p->secret_nb_parts=secret_nb_parts;
		p->common_magic=db->common_magic;
		p->id_holder = id_holder;
		//p->padding[56] a  déjà initialisé à une valeur aléatoire par le constructeur
		p->version=CHUNK_HOLDER_VERSION; 
		p->magic=CHUNK_HOLDER_MAGIC;	

		// On chiffre dans un buffer provisoire car le chunk, dans l'objet t_person, est censé rester en clair		
		unsigned char* partie_aes = (unsigned char*) alloca(CHUNK_HOLDER_AES_SIZE);
		memcpy(partie_aes, (unsigned char*)p+CHUNK_HOLDER_AES_OFFSET, CHUNK_HOLDER_AES_SIZE);
		cw_aes_cbc(partie_aes, CHUNK_HOLDER_AES_SIZE, pkey, p->salt1, 1);

		#ifdef DEBUG
		debug_printf(0,(char*)"%s() %s part[0]=%lx part[7]=%lx\n", __func__, nickname, *(uint64_t*)&parts[0], *(uint64_t*)&parts[7*32]);
		debug_printf(0,(char*)"%s() écriture chunk '%s' état open pkey=%lx\n", (char*)__func__, nickname, *(uint64_t*)pkey);
		debug_printf(0,(char*)"%s() chunk=%lx partie chiffrée=%lx\n", (char*)__func__, *(uint64_t*) chunk, *(uint64_t*) (chunk+CHUNK_HOLDER_AES_OFFSET));
		#endif

		fwrite(chunk, CHUNK_HOLDER_AES_OFFSET, 1, fichier); // Enregistre
		fwrite(partie_aes, CHUNK_HOLDER_AES_SIZE, 1, fichier); // Enregistre
		assert((CHUNK_HOLDER_AES_SIZE+CHUNK_HOLDER_AES_OFFSET) == CHUNK_HOLDER_SIZE);
	} else {
		fprintf(stderr, "%s Runtime line %d file %s\n", __func__,  __LINE__, __FILE__);
		abort();
	}
}

/** 
 *  \brief Génère le json pour cette holder
 *  \return Le node json (créé par json_node_alloc(), à libérer par un unref() 
 *  \note 
 *  - invoqué par t_database::save()
 */
 
#ifdef MPM_GLIB_JSON		
JsonNode *t_holder::save_common() {
	JsonObject *object;
	
	object = json_object_new();
	json_object_set_member (object, "common_nb_parts", json_node_init_int    (json_node_alloc (), common_nb_parts));
	json_object_set_member (object, "secret_nb_parts", json_node_init_int    (json_node_alloc (), secret_nb_parts));	
	json_object_set_member (object, "id_holder",       json_node_init_int    (json_node_alloc (), id_holder));
	json_object_set_member (object, "nickname",        json_node_init_string (json_node_alloc (), nickname));
	json_object_set_member (object, "file_index",      json_node_init_int    (json_node_alloc (), file_index));		
	if (email) 
	json_object_set_member (object, "email",           json_node_init_string (json_node_alloc (), email));
	return json_node_init_object (json_node_alloc (), object);
}
#endif
#ifdef  MPM_JANSSON
json_t *t_holder::save_common() {
	json_t *jso = json_object();
	json_object_set(jso, "common_nb_parts", json_integer(common_nb_parts));
	json_object_set(jso, "secret_nb_parts", json_integer(secret_nb_parts));
	json_object_set(jso, "id_holder",       json_integer(id_holder));
	json_object_set(jso, "nickname",        json_string (nickname));
	json_object_set(jso, "file_index",      json_integer(file_index));
	if (email)
	json_object_set(jso, "email",           json_string (email));
	return jso;
}
#endif


/** 
 *  \brief Calcule le nb de parts disponibles via ce holder
 *  \param[out]	*common_
 *  \param[out] *secret_
 *  \note 
 *    - L'entier pointé est incrémenté, et pas fixé dans l'absolu (pour permettre une boucle facile par l'appelant)
 *    - Dans tous les cas, si les pointeurs passés sont NULL, ne fait rien
 */
void t_holder::compte_parts_disponibles(int *common_, int *secret_) {
	// Les parts sont disponibles si le chunk est ouvert, ou si il est nouvellement créé
	if ( (chunk_status == HOLDER_CHUNK_STATUS_OPEN) || (chunk_status == HOLDER_CHUNK_STATUS_NONE) ) {
		if (common_) *common_ += common_nb_parts;
		if (secret_) *secret_ += secret_nb_parts;
	} 
}

/** 
 *  \brief Calcule le nb de parts distribuées
 *  \param[out]	*common_
 *  \param[out] *secret_
 *  \note 
 *    - L'entier pointé est incrémenté, et pas fixé dans l'absolu (pour permettre une boucle facile par l'appelant)
 *    - Dans tous les cas, si les pointeurs passés sont NULL, ne fait rien
 *    - Ici, on ne décompte pas les parts si le holder n'est pas 'OPEN'
 */
void t_holder::compte_parts_distribuees(int *common_, int *secret_) {
	if (common_) *common_ += common_nb_parts;
	if (secret_) *secret_ += secret_nb_parts;	
}


/** 
 *  \brief Calcule le nb de parts treshold d'après ce holder
 *  \param[out]	*common_
 *  \param[out] *secret_
 *  \note 
 *    - L'entier pointé est fixé à la valeur connue si il était avant à -1
 *    - Si l'entier pointé était déjà != -1, alors on fait juste un check de cohérence, mais rien d'autre
 *    - Rappel : les seuils ne sont pas vraiment une propriété des holders, mais c'est par le premier holder ouvert qu'on le connait le plus tôt
 */
void t_holder::compte_parts_necessaires(int *common_, int *secret_) {
	if ( (chunk_status != HOLDER_CHUNK_STATUS_OPEN) ) {
		return;
	}
	t_chunk_holder *ch = (t_chunk_holder *)chunk;
	if (common_) {
		if (*common_ == -1) {
			*common_ = ch->common_treshold;
		} else {
			if (*common_ != ch->common_treshold) {
				#ifdef DEBUG
				debug_printf(0,(char*)"%s() incoherence nb de parts common pour '%s'\n", __func__, nickname);
				#endif
			}
		}
	}
	if (secret_) {
		if (*secret_ == -1) {
			*secret_ = ch->secret_treshold;
		} else {
			if (*secret_ != ch->secret_treshold) {
				#ifdef DEBUG
				debug_printf(0,(char*)"%s() incoherence nb de parts common pour '%s'\n", __func__, nickname);
				#endif
			}
		}
	}
}
