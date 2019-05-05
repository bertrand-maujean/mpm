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


#include <errno.h>
#include <assert.h>
#include <lb64.h>
#include <inttypes.h> /* pour PRIx64 et autres, qui ne sont pas pas dans stdint.h */
#include <cparser.h>  /* pour CPARSER_MAX_PROMPT */
#include "database.h"



/** 
 *  \brief Constructeur pour l'ouverture d'une base existante sur disque
 *  \note 
 *  - la base est créée avec status=MPM_LEVEL_INIT
 *  - et en fait, on ne fait presque rien, tout se fera avec les try() ultérieurs
 */
t_database::t_database(void) {
	filename = NULL;
	json_root_node=NULL;
	holders=NULL;
	root_folder=current_folder=NULL;
	status=MPM_LEVEL_INIT;
	next_id_holder=1;
	sss_common = sss_secret = NULL;
	nb_holders=0;
	changed=0;
	common_treshold=secret_treshold=-1;
}

/** 
 *  \brief Constructeur pour création d'une nouvelle base initialement vide, connaissant les treshold et nom de fichier
 *  \note la base est créée directement avec status=MPM_LEVEL_SECRET, mais attention, les parts ne sont pas encore distribuées
 *  \TODO Gérer les erreurs sans interaction UI
 */
t_database::t_database(int common_treshold_, int secret_treshold_, char *filename_) : t_database() {
	if (filename_) {
		filename=strdup(filename_);
	} else {
		filename=NULL;
	}
	int err;

	// Initialisation proprement dite - sss common
	sss_common=lsss_new(256, common_treshold_, &err);
	
	if (err!=LSSS_ERR_NOERR) {
		printf("Erreur %d à l'initialisation lsss_ctx()\n", err);
		return;
	}
	random_bytes(common_key, 32);
	lsss_set_secret(sss_common, common_key);

	#ifdef DEBUG
	debug_printf(0,(char*)"%s() nouvelle common key=%" PRIx64 "\n", __func__, *(uint64_t*) common_key);
	#endif


	// sss secret
	sss_secret=lsss_new(256, secret_treshold_, &err);
	if (err!=LSSS_ERR_NOERR) {
		printf("Erreur %d à l'initialisation lsss_ctx()\n", err);
		return;
	}
	random_bytes(secret_key, 32);
	lsss_set_secret(sss_secret, secret_key);
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() nouvelle secret key=%" PRIx64 "\n", __func__, *(uint64_t*) secret_key);
	#endif
	
	common_treshold = common_treshold_;
	secret_treshold = secret_treshold_;	
	random_bytes(&common_magic, 8);
	
	changed=MPM_CHANGED_NEW;
	status=MPM_LEVEL_SECRET;
	
	nb_holders=0;
}


/** 
 *  \brief Destructeur libère les chaines malloc()ées, contextes sss et autres bricoles
 */
t_database::~t_database() {
	//GList *gl;
	tdllist *gl;
	gl = holders;
	while (gl) {
		delete (t_holder*)gl->data;
		gl=gl->next;
	}
	//if (holders) g_list_free(holders);
	if (holders) tdll_free(holders);

	// faire de même avec les secrets
	if (filename) free(filename);

	// Libération du node JSon à faire complexe json_root_node=NULL;
	if (sss_common) lsss_free(sss_common);
	if (sss_secret) lsss_free(sss_secret);

	if (root_folder!=NULL) delete root_folder;
}

/** 
 *  \brief Ajoute des bits dans l'état changé de la base
 */
void t_database::set_changed(int flag) {
	changed |= flag;
}

/** 
 *  \brief Renvoie le dossier racine des secrets
 *  \note Et éventuellement le créé, si ce n'était pas déjà fait
 */
t_secret_folder *t_database::get_root_folder() {
	if (!root_folder) {
		root_folder = new t_secret_folder(NULL, "Racine", 1, this); // pas de parent, nom "racine, et id=1
	}
	return root_folder;
}

/** 
 *  \brief Renvoie le dossier courant des secrets
 */
t_secret_folder *t_database::get_current_folder() {
	if (!current_folder) {
		current_folder = get_root_folder();
	}
	return current_folder;
}

/** 
 *  \brief Fixe le cossier courant des secrets
 */
t_secret_folder *t_database::set_current_folder(t_secret_folder *current_folder_) {
	current_folder = current_folder_;
	return current_folder;
}


/** 
 *  \brief Recherche un ID libre le plus petit possible, pour affecter à un secret ou un dossier
 *  \note Parcours les n° à partir de 1
 *  \note Les ID sont uniques, mais sont recyclés. A chaque fois, on utilise le plus petit disponible
 */
uint32_t t_database::get_free_id() {
	uint32_t i;
	for (i=1; i< MPM_MAX_SECRET_ID; i++) {
		if (root_folder->is_id_free(i)) return i;	
	}
	return 0; // Si pas d'ID disponible, = base pleine ou problème
}


/** 
 *  \brief Génère un prompt en fonction de l'état de la base
 *  \return un pointeur sur le prompt
 *  \note Le prompr est généré dans une variable statique
 *  \todo Gérer correctement la taille de buffer (nb : strncat ne limite que la taille ajoutée, pas la taille totale)
 *  \todo Gérer le suppression du début de fichier si la taille de prompt est trop longue, yc chemin
 */
char *t_database::prompt() {
	static char prompt[CPARSER_MAX_PROMPT];
	memset(prompt, 0, sizeof(prompt));

	if (changed) {
		strncat(prompt, "*", CPARSER_MAX_PROMPT);
	}

	if (filename) {
		if (*filename==0) {
			printf("Runtime error, filename=='\\0'\n");
			free(filename);
			filename=NULL;
		}
		// Traitement pour tronquer éventuellement le nom de fichier, pour en faire un prompt de longueur acceptable
		size_t fnl = strlen(filename);     // Longueur du nom de fichier
		size_t acc = CPARSER_MAX_PROMPT-8; // longueur maximum acceptée

		if (fnl > (acc >>1)) { // Si la longueur du nom est inférieur à la moitié de ce qui est accepté, ne tronque rien
			// Tronque une éventuelle partie '/dossier/'
			char* d=filename+strlen(filename)-1; // se place sur le dernier caractère
			while ( (*d != '\\') && (*d != '/') && (d > filename) ) d--; // Recherche le premier / ou \ en partant de la fin
			if ((*d=='/')||(*d=='\\')) d++;
			if (strlen(d) > acc) { // Si la longueur en supprimant la partie chemin est encore trop grande, on supprime le début
				d += (strlen(d) - acc);
			}
			strncat(prompt, d, CPARSER_MAX_PROMPT);
		} else {
			strncat(prompt, filename, CPARSER_MAX_PROMPT);
		}
	} else {
		strncat(prompt, "(noname)", CPARSER_MAX_PROMPT);
	}

	switch (status) {
		case MPM_LEVEL_INIT : /* Base vide pas encore initialisée */
			strncat(prompt, "(init) ", CPARSER_MAX_PROMPT);
			break;

		case MPM_LEVEL_NONE : /* Base non ouverte, ne peut pas être encore différenciée d'une suite d'octets aléatoires */
			strncat(prompt, "? ", CPARSER_MAX_PROMPT);
			break;

		case MPM_LEVEL_FIRST :  /* Au moins un utilisateur a été reconnu, mais pas encore de quorum "common" */
			strncat(prompt, "! ", CPARSER_MAX_PROMPT);
			break;

		case MPM_LEVEL_COMMON :  /* Base ouverte, on a le quorum "common" */
			strncat(prompt, "> ", CPARSER_MAX_PROMPT);
			break;

		case MPM_LEVEL_SECRET :		
			strncat(prompt, "# ", CPARSER_MAX_PROMPT);
			break;
	}
	return prompt;
}



/** 
 *  \brief Génère un nouvel ID de holder, et incrémente pour le suivant
 *  \return l'ID 
 */
int t_database::get_next_id_holder() {
	int i;
	i = next_id_holder;
	next_id_holder++;
	return i;
}

/** 
 *  \brief Recherche si une holder existe déjà dans la base, d'après son nickname
 *  \return le t_holder*, ou NULL si pas trouvé
 */
t_holder *t_database::find_holder(char *nickname) {
	//GList *gl;
	tdllist *gl;
	t_holder *p;
	p=NULL; 
	gl=holders;
	while(gl) {
		if( ((t_holder*)gl->data)->is_nickname(nickname) ) {
			p=(t_holder*)(gl->data);
			break;
		}
		gl=gl->next;
	}
	return p;
}

/** 
 *  \brief Indique si le contenu de la BDD a été changé ou pas
 *  \note 
 *  - invoqué par l'interface utilisateur pour confirmer la fin du programme, ou adapter le prompt
 */
int t_database::is_changed() {
	return changed;
}

/** 
 *  \brief Fixe ou change le nom de fichier de la base
 *  \note 
 *  - Si il était déjà fixé, le nom existant est libéré par free() et le nouveau allouée par malloc()
 */
void t_database::set_filename(char *fn) {
	if (filename != NULL) free(filename);
	filename=strdup(fn);
	//set_changed(MPM_CHANGED_OTHER);
}

/** 
 *  \brief Sauvegarde l'ensemble du fichier de BDD
 *  \note 
 *  - invoqué par le programme principal/user interface
 *  \todo Rendre cette fonction muette, sans printf
 */
 
 
 /*
tty ../radar2.tty 
dashb -output /dev/pts/3
break -source database.cpp -function t_database::save
dashb expr watch common_treshold
dashb expr watch secret_treshold
dashb expr watch common_total
dashb expr watch secret_total
dashb expr watch secret_tresh
dashb expr watch common_tresh

 */
#ifdef MPM_GLIB_JSON 
void t_database::save() {
	//GList *gl;
	tdllist *gl;
	FILE *file;
	t_common_marker cm;
	GError *gerreur;
	
	// Utilisé pour la génération json
	unsigned char padding[16];
	gchar *json_buffer; // va contenir la base JSON en clair
	unsigned char *aes_buffer;   // le même en chiffré
	int len_aes; // , outl, i;
	JsonGenerator *generator;
	gsize json_len;
	JsonObject *json_root_object;
	JsonArray *json_array;
	JsonNode *json_root_node;

	printf("Sauvegarde du fichier : %s - ", filename);

	file = fopen(filename, "w+b");
	if (!file) {
		printf("Erreur à l'ouverture du fichier\n");
		perror(NULL);
		printf("\n");
		return;
	}

	// Enregistre les chunks de holders
	int i = 0;
	gl = holders;
	while (gl) {
		((t_holder*)gl->data)->file_index=i;
		((t_holder*)gl->data)->save_chunk(file);
		gl=gl->next; i++;
	}
		
	// Enregistre le marqueur pour la partie common/json
	random_bytes((void*)cm.salt, 32);
	//cw_database_save_cm(cm.salt, common_magic, cm.hash);
	cw_sha256_mix2(cm.hash, cm.salt, common_magic);
	fwrite(&cm, sizeof(cm), 1, file);
	
	
	// Génére la BDD en json
	generator = json_generator_new ();
	json_root_object = json_object_new();
	
	json_object_set_member (json_root_object, "common_treshold", json_node_init_int (json_node_alloc (), common_treshold));
	json_object_set_member (json_root_object, "secret_treshold", json_node_init_int (json_node_alloc (), secret_treshold));
	json_object_set_member (json_root_object, "next_id_holder", json_node_init_int (json_node_alloc (), next_id_holder));

	// Charge les holders
	json_array = json_array_new();
	gl = holders;
	while (gl) {
		json_array_add_element(json_array, ((t_holder*)gl->data)->save_common());
		gl=gl->next;
	}
	json_object_set_member (json_root_object, "holders", json_node_init_array (json_node_alloc (), json_array));
	

	// Raccroche les branches de dossiers et secrets
	if (root_folder) {
		json_object_set_member (json_root_object, "root_folder", root_folder->save());
	}


	// Raccroche au générateur, et génère
	json_root_node = json_node_init_object (json_node_new(JSON_NODE_OBJECT), json_root_object);
	json_generator_set_root (generator, json_root_node);
	json_buffer = json_generator_to_data (generator, &json_len);
	
	json_generator_set_pretty (generator, TRUE); // Pour debug uniquement
	json_generator_set_indent (generator, 4);	 // Pour debug uniquement
	json_generator_to_file (generator, "mpm.debug.json", &(gerreur=NULL)); // Pour debug uniquement
	if (gerreur) {
		fprintf(stderr, "runtime error %s %s %d glib : %s\n", __func__, __FILE__, __LINE__, gerreur->message); 
	}
	json_node_unref(json_root_node); // supposé tout librer récursivement par le jeu de ref/unref
	g_object_unref ((gpointer) generator);


	// Chiffrement
	aes_buffer = (unsigned char*)malloc(json_len+64); // normalement 31 devrait suffire, padding de 16 + arrondi dernier bloc AES de 15
	//memset(aes_buffer, 0, json_len+64); tenté pour supprimé une alerte valgrind de mémoire non initialisée
	memcpy(aes_buffer, json_buffer, json_len);
	*(aes_buffer+json_len)=0; // Ajoute un /0 pour le décodage
	memcpy(aes_buffer+json_len+1, "MAGICCOM", 8); // pour le test d'intégrité de la partie common/json
	len_aes=(json_len+24)&0xfffffffffffffff0;	
	cw_aes_cbc(aes_buffer, len_aes, common_key, (unsigned char*)&cm, 1);

	// Ecrit le fichier
	fwrite(aes_buffer, len_aes, 1, file);
	fflush(file);
	g_free(json_buffer);
	free(aes_buffer);

	// ecrit 0 à 15 octets aléatoires en plus, pour qu'on ne voit pas la longueur multiple de 16
	random_bytes(padding, 16);
	fwrite(padding, (int)(padding[15]&0xf), 1, file); // le dernier char n'est jamais écrit dans le fichier, mais il sert à déterminer la longueur
	fflush(file);

	fclose(file); 
	changed=0;
	printf("Fait\n\n");
	
}
#endif /* GLIB_JSON */

#ifdef  MPM_JANSSON
void t_database::save() {
	tdllist *gl;
	FILE *file;
	t_common_marker cm;
	
	unsigned char padding[16];
	unsigned char *aes_buffer;   // le même en chiffré
	int len_aes; // , outl, i;

	printf("Sauvegarde du fichier : %s - ", filename);

	file = fopen(filename, "w+b");
	if (!file) {
		printf("Erreur à l'ouverture du fichier\n");
		perror(NULL);
		printf("\n");
		return;
	}

	// Enregistre les chunks de holders
	int i = 0;
	gl = holders;
	while (gl) {
		((t_holder*)gl->data)->file_index=i;
		((t_holder*)gl->data)->save_chunk(file);
		gl=gl->next; i++;
	}
		
	// Enregistre le marqueur pour la partie common/json
	random_bytes((void*)cm.salt, 32);
	cw_sha256_mix2(cm.hash, cm.salt, common_magic);
	fwrite(&cm, sizeof(cm), 1, file);
	fflush(file);
	
	// Génére la BDD en json et ajoute les paramètres scalaires
	json_t *js_root = json_object();
	if (-1 == json_object_set(js_root, "common_treshold",   json_integer(common_treshold))) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
		#endif
	}
	if (-1 == json_object_set(js_root, "secret_treshold",   json_integer(secret_treshold))) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
		#endif
	}
	if (-1 == json_object_set(js_root, "next_id_holder",   json_integer(next_id_holder))) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
		#endif
	}
	
	// Charge les holders
	json_t *jsha = json_array();
	gl = holders;
	while (gl) {
		if (-1 == json_array_append(jsha, ((t_holder*)gl->data)->save_common()  )) {
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
			#endif	
		}
		gl=gl->next;
	}
	json_object_set(js_root, "holders", jsha); 

	// Raccroche les branches de dossiers et secrets
	if (root_folder) {
		json_object_set(js_root, "root_folder", root_folder->save());
	}

	// Raccroche au générateur, et génère
	char *json_buffer = json_dumps(js_root, JSON_INDENT(4) ); // Génère le flux json
	if (json_buffer == NULL) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() %s:%d runtime sur jansson\n", __func__, __FILE__, __LINE__);
		#endif			
	} 
	json_decref(js_root); // supprime l'arbre Jansson en mémoire
	
	int json_len = strlen(json_buffer);
	#ifdef DEBUG
	{
		FILE *f=fopen("mpm.debug.json","w+b");
		fwrite(json_buffer, json_len, 1, f);
		fclose(f);
	}
	#endif
	
	
	// Chiffrement
	aes_buffer = (unsigned char*)malloc(json_len+64); // normalement 31 devrait suffire, padding de 16 + arrondi dernier bloc AES de 15
	memcpy(aes_buffer, json_buffer, json_len);
	*(aes_buffer+json_len)=0; // Ajoute un /0 pour le décodage
	memcpy(aes_buffer+json_len+1, "MAGICCOM", 8); // pour le test d'intégrité de la partie common/json
	len_aes=(json_len+24)&0xfffffffffffffff0;	
	cw_aes_cbc(aes_buffer, len_aes, common_key, (unsigned char*)&cm, 1);

	// Ecrit le fichier
	fwrite(aes_buffer, len_aes, 1, file);
	fflush(file);
	free(json_buffer);
	free(aes_buffer);
	

	// ecrit 0 à 15 octets aléatoires en plus, pour qu'on ne voit pas la longueur multiple de 16
	random_bytes(padding, 16);
	fwrite(padding, (int)(padding[15]&0xf), 1, file); // le dernier char n'est jamais écrit dans le fichier, mais il sert à déterminer la longueur
	fflush(file);
	fclose(file); 
	changed=0;
	printf("Fait\n\n");
}
#endif /* JANSSON */


/** 
 *  \brief Recherche un chunk de holder dans le fichier étant donnée un nickname et MdP
 *  \return pointeur sur un bloc nouvellement malloc()é pour contenir le chunk déchiffré, ou NULL si raté
 *  \param[in]   nickname    Le nickname utilisé en entrée pour la crypto
 *  \param[in]   password    Le password qu'on utilise avec dans le test crypto
 *  \param[out]  file_index  Renseigne le file_index, si le chunk a été trouvé
 *  \param[out]  pkey        Renseigne la clé de holder, si le chunk a été trouvé. Doit être conservé pour le save() (des fois que la holder ne change pas son MdP, on ne saurait pas la recalculer)
 *  \note 
 *  - invoqué par t_database::try_nickname() dans le cas ou la base n'est pas encore ouverte au niveau common
 *  - teste les blocs de CHUNK_HOLDER_SIZE à la suite, et teste le hash pour voir si ça correspond
 *  - max_holder indique le nombre max de chunks à tenter. passer 0 si on ne connait pas encore le nb de holders, ce qui est le cas pour le tout premier try
 */
t_chunk_holder * t_database::find_chunk_holder(char *nickname, char *password, int *file_index, unsigned char *pkey) {
	FILE *f;
	t_chunk_holder *chunk, *find_chunk;
	t_common_marker *cm;
	int lus, i;
	unsigned char hash_calcule[32];
	bool trouve_holder;
	bool trouve_common;

	find_chunk=NULL;
	chunk = (t_chunk_holder*)alloca(CHUNK_HOLDER_SIZE);
	cm = (t_common_marker*)chunk;
	f = fopen(filename,"r+b"); /* Note : sous Windows, ne pas oublier le '+b' */
	i=0;
	trouve_holder=trouve_common=false;
	while (!feof(f)) {
		lus=fread(chunk, 1, CHUNK_HOLDER_SIZE, f);
		#ifdef DEBUG 
		debug_printf(0, (char*)"Lu le bloc no %d de taille %d\n", i, lus);
		#endif
		if (!trouve_holder) if (lus == CHUNK_HOLDER_SIZE) {	
			//cw_database_find_chunk_holder_hash(nickname, (unsigned char*)chunk->salt1, password, (unsigned char*)hash_calcule);
			cw_sha256_iterated_mix1(hash_calcule, nickname, chunk->salt1, password);
			
			if (memcmp(chunk->hash,hash_calcule,32 ) ==0) { // chunk trouvé
				#ifdef DEBUG 
				debug_printf(0, (char*)"%s() f=%s l=%d chunk trouvé en position %d\n",(char*)__func__,(char*) __FILE__, __LINE__, i);
				#endif
				trouve_holder=true; 
				if (file_index) *file_index=i;


				find_chunk=(t_chunk_holder*)malloc(CHUNK_HOLDER_SIZE);
				//memcpy((void*)find_chunk, (void*)chunk, CHUNK_HOLDER_SIZE); // nb : la partie chiffrée est recopiée pour rien
				//cw_database_find_chunk_holder_pkey(nickname, (unsigned char*)chunk->salt2, password, (unsigned char*)hash_calcule);
				cw_sha256_iterated_mix1(hash_calcule, nickname, chunk->salt2, password);
				//cw_holder_dechiffre_chunk((unsigned char*)find_chunk, (unsigned char*)chunk, (unsigned char*)hash_calcule, chunk->salt1);
				cw_aes_cbc((unsigned char*)chunk + CHUNK_HOLDER_AES_OFFSET, CHUNK_HOLDER_AES_SIZE, hash_calcule, chunk->salt1, 0);
				memcpy((void*)find_chunk, (void*)chunk, CHUNK_HOLDER_SIZE);
				if (pkey) memcpy(pkey, (unsigned char*)hash_calcule, 32); 
			}
		}
		if (trouve_holder & !trouve_common) {
			//cw_database_find_chunk_common((unsigned char*)cm->salt, find_chunk->common_magic, (unsigned char*)hash_calcule);
			cw_sha256_mix2(hash_calcule, cm->salt, find_chunk->common_magic);
			if (memcmp(cm->hash, hash_calcule, 32)==0) {
				#ifdef DEBUG
				debug_printf(0,(char*)"%s() Marqueur 'common' trouvé en position %d\n", (char*)__func__, i);
				#endif
				if (nb_holders==0) {
					nb_holders=i;
				} else {
					if (nb_holders != i) {
						#ifdef DEBUG
						debug_printf(0, (char*)"%s() incohérence nb_holders=%d i=%d\n",(char*)__func__,nb_holders, i);
						#endif
					}
				}
				break;
			}
		}
		i++;
	}
	fclose(f);	
	return find_chunk;
}

/** 
 *  \brief Calcule le nb de parts disponibles dans la base
 *  \note 
 *  - invoqué par t_database::check_level()
 *  - parcours de la fonction de même nom dans les holders
 */
void t_database::compte_parts_disponibles(int *common_, int *secret_) {
	if (common_) *common_ = 0;
	if (secret_) *secret_ = 0;
	for (/*GList*/ tdllist *gl = holders; gl!=NULL; gl=gl->next) {
			((t_holder*)gl->data)->compte_parts_disponibles(common_, secret_);
	}
}

void t_database::compte_parts_distribuees(int *common_, int *secret_) {
	if (common_) *common_ = 0;
	if (secret_) *secret_ = 0;
	for (/*GList*/ tdllist *gl = holders; gl!=NULL; gl=gl->next) {
			((t_holder*)gl->data)->compte_parts_distribuees(common_, secret_);
	}
}

void t_database::compte_parts_necessaires(int *common_, int *secret_) {
	if (common_) *common_ = common_treshold;
	if (secret_) *secret_ = secret_treshold;
	for (/*GList*/ tdllist *gl = holders; gl!=NULL; gl=gl->next) {
			((t_holder*)gl->data)->compte_parts_necessaires(common_, secret_);
	}
}



/** 
 *  \brief Lecture de la BDD common dans le fichier, après reconstitution de la clé
 *  \note 
 *  - invoqué par t_database::open_common()
 *  - traite la partie crypto avant d'invoquer t_database::read_json()
 *  - les structures glib-json sont allouées et libérées ici (principe ref/unref des g_object)
 */
void t_database::read_common() {
	long filesize;
	long common_pos, lus, taille;
	FILE *file;
	unsigned char *buffer_chiffre;
	unsigned char iv[16];

	file = fopen(filename, "r+b");
	if (file==NULL) {
		fprintf(stderr, "Erreur à l'ouverture du fichier %s (%s)\n", filename, strerror(errno));
		return;
	}

	fseek(file, 0, SEEK_END);
	filesize=ftell(file);

	// Lis le marqueur de détection du chunk common, dont les 16 premiers octets servent d'IV
	common_pos = nb_holders*CHUNK_HOLDER_SIZE;
	fseek(file, common_pos, SEEK_SET);
	fread (iv, 1, 16, file);

	// repositionne pour le contenu chiffré
	common_pos += sizeof(t_common_marker);
	taille=(filesize-common_pos)&(0xfffffffffffffff0);
	fseek(file, common_pos, SEEK_SET); // nb : on a lu que 16 octets pour l'IV, donc il faut se positionner

	buffer_chiffre = (unsigned char*)malloc(taille+32);

	#ifdef DEBUG
	debug_printf(0,(char*)"%s() taille=%d common_pos=%d\n", __func__, taille, common_pos);
	#endif	

	lus = fread(buffer_chiffre, 1, taille, file);
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() lus=%d\n", __func__, lus);
	#endif

	if (lus != taille) {
		fprintf(stderr, "Taille lue dans le fichier incohérente\n");
	}

	//cw_database_common_dechiffre(common_key, iv, buffer_clair, buffer_chiffre, taille );
	cw_aes_cbc(buffer_chiffre, taille, common_key, iv, 0);
	fclose(file);

	// Vérifie la présence du MAGIC en fin du buffer json
	// doit se terminer par "MAGICCOM\0"
	bool ok=true;
	ok = (strlen((char*)buffer_chiffre) > 20);
	if (ok) ok = (memcmp(&buffer_chiffre[strlen((char*)buffer_chiffre)+1], "MAGICCOM", 8) ==0);

	
	// Interprete le json
	if (ok) {
	
		#ifdef MPM_GLIB_JSON
		JsonParser *parser = json_parser_new ();
		GError *err = NULL;
		if (!json_parser_load_from_data (parser, (const char*)buffer_chiffre, strlen((const char*)buffer_chiffre), &err)) {
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() Erreur json_parser_load_from_data() GError=%s\n", __func__, err->message);
			#endif		
			g_clear_error (&err);
		} else {
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() json parsé avec succès\n", __func__);
			#endif		
		}
		read_json(json_parser_get_root (parser));
		g_object_unref((gpointer)parser);
		#endif
		#ifdef  MPM_JANSSON
		json_error_t err;
		json_t * js = json_loads((const char*)buffer_chiffre, JSON_DISABLE_EOF_CHECK, &err);
		if (js) {
			read_json(js);
			json_decref(js); // Supprime l'arbre json en mémoire
		} else {
			#ifdef DEBUG
			debug_printf(0, (char*)"%s() Erreur json_loads() json_err=%s\n", __func__, err.text);
			#endif			
		}
		#endif
				
	} else {
		printf("Erreur d'intégrité de la base 'common'\n");
		printf("La base est probablement inutilisable\n");
	}
	free(buffer_chiffre);
	
}


/** 
 *  \brief Interpretation du json à l'ouverture du niveau 'common'
 *  \param[in] node Le node Json
 *  \note 
 *  - invoqué par t_database::read_common()
 *  - Créé les holders qui n'ont pas encore été ouvertes par new t_holder(), ou complète celles qui l'ont déjà été  par t_holder::complete_ouverture()
 */
 
#ifdef MPM_GLIB_JSON
void t_database::read_json(JsonNode *node) {

	JsonObject *root_object = json_node_get_object (node);
	if ( common_treshold != json_object_get_int_member (root_object, "common_treshold")) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur de cohérence common_treshold\n", __func__);
		#endif	
	}

	if ( secret_treshold != json_object_get_int_member (root_object, "secret_treshold")) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur de cohérence secret_treshold\n", __func__);
		#endif	
	}
	next_id_holder = json_object_get_int_member (root_object, "next_id_holder");
	#ifdef DEBUG
	debug_printf(0, (char*)"%s() next_id_holder=%d\n", __func__, next_id_holder);
	#endif	

	JsonArray *holders_array = json_object_get_array_member (root_object, "holders");

	#ifdef DEBUG
	debug_printf(0, (char*)"%s() nombre de holders dans le json = %d\n", __func__, json_array_get_length (holders_array));
	#endif		

	// traitement de l'ensemble des holders
	GList *gl = json_array_get_elements(holders_array);
	t_holder* p;
	JsonObject *o;
	while (gl) {
		o = json_node_get_object((JsonNode *)gl->data);
		p = find_holder((char*)json_object_get_string_member(o, "nickname"));
		if (p == NULL) {
			p = new t_holder(this, o);
			//holders = g_list_append(holders, p);
			holders = tdll_append(holders, p);
		} else {
			p->complete_ouverture(o);
		}
		gl = gl->next;
	}
	
	assert(root_folder == NULL); // La base n'est pas censée être déjà chargée
	if (json_object_has_member(root_object, "root_folder")) { 
		// Nb : on peut avoir sauvegardé une base sans secret, et donc sans root folder...
		// Elle sera certainement créée juste après
		root_folder = new t_secret_folder(json_object_get_object_member (root_object, "root_folder"), NULL, this);
	}
}
#endif


#ifdef  MPM_JANSSON
void t_database::read_json(json_t *node) {
	if ( common_treshold != json_integer_value(json_object_get(node, "common_treshold"))) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur de cohérence common_treshold\n", __func__);
		#endif	
	}

	if ( secret_treshold != json_integer_value(json_object_get(node, "secret_treshold"))) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() Erreur de cohérence secret_treshold\n", __func__);
		#endif	
	}
	next_id_holder = json_integer_value(json_object_get(node, "next_id_holder"));
	#ifdef DEBUG
	debug_printf(0, (char*)"%s() next_id_holder=%d common=%d secret=%d\n", __func__, next_id_holder, common_treshold, secret_treshold);
	#endif	

	json_t *holders_array = json_object_get(node, "holders");
	if (holders_array == NULL) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() branche holders non trouvée\n", __func__);
		#endif		
	}
	if (!json_is_array(holders_array)) {
		#ifdef DEBUG
		debug_printf(0, (char*)"%s() branche holders n'est pas un array\n", __func__);
		#endif		
	}
	
	int n = json_array_size(holders_array);
	for (int i=0; i<n; i++) {
		// Lecture d'un holder
		json_t *jsh = json_array_get(holders_array, i);
		t_holder* p = find_holder((char*)json_string_value(json_object_get(jsh, "nickname")));
		if (p == NULL) {
			// Cas d'un holder pas encore ouvert
			p = new t_holder(this, jsh);
			holders = tdll_append(holders, p);
		} else {
			// cas d'un holder qui avait déjà donné ses parts avant l'ouverture common
			p->complete_ouverture(jsh);
		}		
	}

	assert(root_folder == NULL); // La base n'est pas censée être déjà chargée
	if (json_t *jsrf = json_object_get(node, "root_folder")) { 
		// Nb : on peut avoir sauvegardé une base sans secret, et donc sans root folder...
		// Elle sera certainement créée juste après
		root_folder = new t_secret_folder(jsrf, NULL, this);
	}
}
#endif


/** 
 *  \brief Reconstitue la clé du niveau common
 *  \note 
 *  - invoqué t_database::check_level()
 *  - Suppose que le nombre de part est atteint. Ce point a déjà été vérifié par check_level(). Runtime error sinon
 *  -  puis appelle read_common() pour lire la base common dans le fichier
 */
void t_database::open_common() {
	/*GList*/ tdllist *gl;
	t_holder *p;
	int i, err;
	bool encore;
	
	// Normalement, si on arrive ici, le contexte lsss n'est pas encore créé
	if (sss_common) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() incoherence sss_common déjà alloué f=%s l=%d\n", __func__, __FILE__, __LINE__);
		#endif			
	} else {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() création du sss_common avec quorum de %d parts\n", __func__, common_treshold);
		#endif	
		sss_common=lsss_new(256, common_treshold, &err);
		if (err != LSSS_ERR_NOERR) {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() erreur lsss %d f=%s l=%d\n", __func__, err, __FILE__, __LINE__);
			#endif
		}
	}

	gl = holders;
	encore=true;
	while (gl && encore) {
		p=((t_holder*)gl->data);
		for (i=0; (i<p->common_nb_parts) && encore; i++) {
			encore = (lsss_set_part(sss_common, &(p->parts[i*32]), uint64_t (p->xparts[i]) ) != LSSS_ERR_MANY_PARTS);
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() chargement part x=%lx y=%lx\n", __func__, uint64_t (p->xparts[i]), *(uint64_t*) &(p->parts[i*32]) );
			#endif			
		}
		gl=gl->next;
	}

	if (lsss_missing_parts(sss_common) != 0) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() incoherence sss_common pas assez de parts f=%s l=%d\n", __func__, __FILE__, __LINE__);
		#endif
	}

	sss_common->recoef=true;
	err = lsss_combine(sss_common);
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() f=%s l=%d lsss_combine() renvoie %d\n", __func__, __FILE__, __LINE__, err);
	#endif
	if (err != LSSS_ERR_NOERR) {
		fprintf(stderr, "Erreur à la recombinaison\n"); 
	}
	lsss_get_secret(sss_common, common_key);

	#ifdef DEBUG
	debug_printf(0,(char*)"%s() secret retrouvé=%lx\n", __func__, *(uint64_t*)common_key);
	#endif

	read_common();
}





/** 
 *  \brief Reconstitue la clé du niveau secret
 *  \note 
 *  - invoqué t_database::check_level()
 *  - Suppose que le nombre de part est atteint. Ce point a déjà été vérifié par check_level(). Runtime error sinon
 */
void t_database::open_secret() {
	int err,i;
	t_holder* p;

	// Normalement, si on arrive ici, le contexte lsss n'est pas encore créé
	if (sss_secret) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() incoherence sss_secret déjà alloué f=%s l=%d\n", __func__, __FILE__, __LINE__);
		#endif
	} else {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() création du sss_secret avec quorum de %d parts\n", __func__, secret_treshold);
		#endif	
		sss_secret=lsss_new(256, secret_treshold, &err);
		if (err != LSSS_ERR_NOERR) {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() erreur lsss %d f=%s l=%d\n", __func__, err, __FILE__, __LINE__);
			#endif
		}
	}


	/*GList*/ tdllist* gl = holders;
	bool encore=true;
	uint64_t x;
	unsigned char *y;
	
	while (gl && encore) {
		p=((t_holder*)gl->data);
		for (i=0; (i<p->secret_nb_parts) && encore; i++) {
			if (p->chunk_status == HOLDER_CHUNK_STATUS_OPEN) {
				x = p->xparts[(CHUNK_MAX_PARTS-1-i)];
				y = &p->parts[(CHUNK_MAX_PARTS-1-i)*32];
				encore = (lsss_set_part(sss_secret, y, x) != LSSS_ERR_MANY_PARTS);
				#ifdef DEBUG
				debug_printf(0,(char*)"%s() chargement part x=%lx y=%lx..%lx\n", __func__, x, *(uint64_t*) y , *(uint64_t*) (y+24));
				#endif
			}
		}
		gl=gl->next;
	}
	
	if (lsss_missing_parts(sss_secret) != 0) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() incoherence sss_secret pas assez de parts f=%s l=%d\n", __func__, __FILE__, __LINE__);
		#endif			
	}
	
	sss_secret->recoef=true;
	err = lsss_combine(sss_secret);
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() f=%s l=%d lsss_combine() renvoie %d\n", __func__, __FILE__, __LINE__, err);
	#endif
	if (err != LSSS_ERR_NOERR) {
		fprintf(stderr, "Erreur à la recombinaison\n"); 
	}
	lsss_get_secret(sss_secret, secret_key);
	
	#ifdef DEBUG
	debug_printf(0,(char*)"%s() secret retrouvé=%lx\n", __func__, *(uint64_t*)secret_key);
	#endif	
}

/** 
 *  \brief Vérifie si on peut élever le niveau ouvert, avec les parts disponibles
 *  \note 
 *  - Appelle open_common() ou open_secret() éventuellement
 *  - Utilise calcule_total_parts_trest() pour compter les parts disponibles
 */
void t_database::check_level() {
	int common_total, secret_total;
	int common_tresh_, secret_tresh_; // treshold détectés dans les chunk ouverts

	compte_parts_disponibles(&common_total, &secret_total);
	compte_parts_necessaires(&common_tresh_, &secret_tresh_);

	#ifdef DEBUG
	debug_printf(0,(char*)"%s() nb total de parts dispo %d/%d nécessaire %d/%d\n", __func__, common_total, secret_total,common_tresh_, secret_tresh_);
	#endif
	/* MPM_LEVEL_INIT  Base vide pas encore initialisée */
	/* MPM_LEVEL_NONE  Base non ouverte, ne peut pas être encore différenciée d'une suite d'octets aléatoires */
	/* MPM_LEVEL_FIRST  Au moins un utilisateur a été reconnu, mais pas encore de quorum "common" */
	/* MPM_LEVEL_COMMON  Base ouverte, on a le quorum "common" */
	/* MPM_LEVEL_SECRET  Base complètement ouverte, on a le quorum "secret" */ 

	if ((status == MPM_LEVEL_NONE) && (common_total >0)) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() passe de MPM_LEVEL_NONE à MPM_LEVEL_FIRST\n", __func__);
		#endif
		common_treshold=common_tresh_;
		secret_treshold=secret_tresh_;
		status = MPM_LEVEL_FIRST;
	}

	if ((status == MPM_LEVEL_FIRST) && (common_total >= common_tresh_)) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() passe de MPM_LEVEL_FIRST à MPM_LEVEL_COMMON\n", __func__);
		#endif
		open_common();
		status = MPM_LEVEL_COMMON;
	}	

	if ((status == MPM_LEVEL_COMMON) && (secret_total >= secret_tresh_)) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() passe de MPM_LEVEL_COMMON à MPM_LEVEL_SECRET\n", __func__);
		#endif
		open_secret();
		status = MPM_LEVEL_SECRET;
	}
	return;
}




/** 
 *  \brief Essaie d'ouvrir les parts d'une holder
 *  \param[in] nickname, password Les informations du porteurs qui sont utilisées en données d'entrée de la crypto
 *  \param[out] apporte_common, apporte_secret Si non NULL, rensiegne l'appelant sur le nombre de parts découvertes
 *  \return Code d'erreur
 *  - MPM_TRY_OK  
 *  - MPM_TRY_NOT_FOUND 
 *  - MPM_TRY_ALREADY_OPENED
 *  - MPM_TRY_INCONSISTENT
 *  \note
 *  - Le fonctionnement est différent selon que le niveau common est déjà ouvert ou pas
 *  - si 'status' est à MPM_LEVEL_COMMON ou MPM_LEVEL_SECRET alors on invoque t_holder::try_tardif()
 *  - sinon, on utilise t_database::find_chunk_holder() puis on créé un nouveau t_holder (dont l'ouverture sera complétée ensuite par t_holder::complete_ouverture() )
 *  - invoque check_level(), sauf si on est déjà en MPM_LEVEL_SECRET
 */
int t_database::try_nickname(char *nickname, char *password, int *apporte_common, int *apporte_secret) {
	t_chunk_holder *chunk;
	t_holder *p;
	int file_index;
	unsigned char pkey[32];

	p = find_holder(nickname);

	if ((status == MPM_LEVEL_COMMON) || (status == MPM_LEVEL_SECRET)) {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() nn=%s status COMMON ou SECRET\n", __func__, nickname);
		#endif
	
		// ouverture alors qu'on a déjà lu la base common : travail en mémoire, tout le monde est déjà chargé
		if (p == NULL) {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() %s non trouvé\n", __func__, nickname);
			#endif	
			return MPM_TRY_NOT_FOUND;
		}
		if (p->chunk_status == HOLDER_CHUNK_STATUS_OPEN) {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() %s déjà en HOLDER_CHUNK_STATUS_OPEN\n", __func__, nickname);
			#endif	
			return MPM_TRY_ALREADY_OPENED;	
		}

		if (p->chunk_status != HOLDER_CHUNK_STATUS_CLOSED) {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() Erreur ! %s pas en HOLDER_CHUNK_STATUS_CLOSED\n", __func__, nickname);
			#endif	
			return MPM_TRY_ALREADY_OPENED;	
		}

		if (p->try_tardif(password)==MPM_TRY_OK) {
			if (apporte_common) *apporte_common = p->common_nb_parts;
			if (apporte_secret) *apporte_secret = p->secret_nb_parts;		
		} else {
			#ifdef DEBUG
			debug_printf(0,(char*)"%s() %s try tardif échoué\n", __func__, nickname);
			#endif
			return MPM_TRY_NOT_FOUND;
		}
	} else {
		#ifdef DEBUG
		debug_printf(0,(char*)"%s() nn=%s status autre que COMMON ou SECRET\n", __func__, nickname);
		#endif		
	
		// Ouverture depuis le fichier, dans le cas où on a pas encore ouvert la base common/json	
		chunk = find_chunk_holder(nickname, password, &file_index, pkey); // le déchiffrement de la partie chiffrée est fait ici
		if (chunk) {
			if (p == NULL) {
				// Ajouter le chunk nouvellement ouvert
				#ifdef DEBUG
				if (chunk->magic != CHUNK_HOLDER_MAGIC) {
					debug_printf(0,(char*)"%s() chunk holder magic incorrect\n", __func__, nickname);
				}
				#endif
				p = new t_holder(nickname, this, chunk, file_index, pkey);
				free(chunk); // nb a été créé avec malloc(), a été recopié, ne sera plus utilisé
				//holders = g_list_append(holders, p);
				holders = tdll_append(holders, p);
				if (apporte_common) *apporte_common = p->common_nb_parts;
				if (apporte_secret) *apporte_secret = p->secret_nb_parts;
				p->chunk_status = HOLDER_CHUNK_STATUS_OPEN;
			} else {	
				if (memcmp(p->chunk, chunk, CHUNK_HOLDER_SIZE)) {
					#ifdef DEBUG
					debug_printf(0,(char*)"%s() dejà ouvert mais chunk incohérent\n", __func__);
					#endif
					return MPM_TRY_INCONSISTENT;
				} else {
					return MPM_TRY_ALREADY_OPENED;
				}
			}
		} else { // chunk == NULL
			return MPM_TRY_NOT_FOUND;
		}
	}

	// Essaie de passer au niveau d'ouverture suivant
	if (status != MPM_LEVEL_SECRET) check_level();
	return MPM_TRY_OK;
}


/** 
 *  \brief Renvoie l'état d'ouverture de la base, constantes MPM_LEVEL_xxx
 */
int t_database::get_status() {
	return status;
}