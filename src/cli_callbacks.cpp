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


#ifdef __linux__
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>

#include <cparser.h>
#include "cparser_tree.h"
#include "mpm.h"



/********************************************************
 * Petits compléments pour la couleur
 * https://en.wikipedia.org/wiki/ANSI_escape_code
 ********************************************************/

int cli_use_ansi = 0; // indique si on peut utiliser les codes ansi ou pas

// Fonction appelée depuis le main en fait, mais définie ici pour la cohérence
void cli_color_white_bg() { // Met le fond en blanc
	if (!cli_use_ansi) return;
    printf("\x1b[30;106m");
	fflush(stdout);
}

void cli_color_rgb(int r, int g, int b) {
	if (!cli_use_ansi) return;
    printf("\x1b[38;2;%d;%d;%dm", r,g,b);
	fflush(stdout);
}

void cli_color_256(int n) {
	if (!cli_use_ansi) return;
    printf("\x1b[38;5;%dm", n);
	fflush(stdout);
}

void cli_ansi_sgr(int n) {
	if (!cli_use_ansi) return;
    printf("\x1b[%dm", n);
	fflush(stdout);
}

void cli_ansi_reset() {
	if (!cli_use_ansi) return;
    printf("\x1b[0m");
	fflush(stdout);
}

#define MPM_COLOR_INPUT   cli_color_256(0); /* les entrées via la CLI : noir */
#define MPM_COLOR_OUTPUT  cli_color_256(4); /* Les messages du programme, hors valeurs et secret : bleu */
#define MPM_COLOR_VALUE   cli_color_256(2); /* Les valeurs des champs : vert */
#define MPM_COLOR_SVALUE  cli_color_256(207); /* Les valeurs secrètes : rose/violet */
#define MPM_COLOR_ERROR   cli_color_256(202); /* Les valeurs secrètes : orange */
#define MPM_ANSI_TERM_BOXED cli_ansi_sgr(4); 
#define MPM_ANSI_TERM_NOBOX cli_ansi_sgr(24); 


/********************************************************
 * Petits compléments à la lib cli_parser
 ********************************************************/
void cparser_change_current_prompt(cparser_context_t *context, char *new_prompt) {
        if (new_prompt) {
                strncpy(&context->parser->prompt[context->parser->root_level][0], new_prompt, CPARSER_MAX_PROMPT);
        }
}


void cparser_change_current_prompt0(cparser_context_t *context, char *new_prompt) {
        if (new_prompt) {
                strncpy(&context->parser->prompt[0][0], new_prompt, CPARSER_MAX_PROMPT);
        }
}

/*
void cparser_change_current_prompt1(cparser_context_t *context, char *new_prompt) {
        if (new_prompt) {
                strncpy(&context->parser->prompt[1][0], new_prompt, CPARSER_MAX_PROMPT);
        }
}
*/

/** fgets amélioré, enlève le LF final et n'affiche pas l'echo */
char *cli_input_no_echo(char *line, int len) {
        int i;	
	#ifdef __linux__
        struct termios oflags, nflags;
        tcgetattr(fileno(stdin), &oflags);
        nflags = oflags;
        nflags.c_lflag &= ~ECHO;
        nflags.c_lflag |= ECHONL;
		nflags.c_lflag |= ICANON;
        if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
                fprintf(stderr, "Runtime erreor file %s line %d\n", __FILE__, __LINE__);
                perror("tcsetattr");
                abort();
        }

        fgets(line, len, stdin);
        i = strlen(line); if (i>0) if (line[i-1] == 10) line[i-1]=0;

        if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
                fprintf(stderr, "Runtime erreor file %s line %d\n", __FILE__, __LINE__);
                perror("tcsetattr");
                abort();
        }
        return line;
	#else
	    DWORD mode;
	    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
	    GetConsoleMode(console, &mode);
		mode |= (ENABLE_LINE_INPUT );
		mode &= ~ENABLE_ECHO_INPUT;
	    SetConsoleMode(console, mode );		
		
        fgets(line, len, stdin);
		puts(""); // Windows ne semble pas faire d'écho au \n entré par l'utilisateur...
        i = strlen(line); if (i>0) if (line[i-1] == 10) line[i-1]=0;	
		return line;
	#endif
}

/** fgets amélioré, enlève le LF final, mais affiche l'écho */
char *cli_input(char *line, int len) {
        int i;
	#ifdef __linux__
        struct termios oflags, nflags;
        tcgetattr(fileno(stdin), &oflags);
        nflags = oflags;
        nflags.c_lflag |= ECHO;
        nflags.c_lflag |= ECHONL;
		nflags.c_lflag |= ICANON;
        if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
                fprintf(stderr, "Runtime erreor file %s line %d\n", __FILE__, __LINE__);
                perror("tcsetattr");
                abort();
        }

        fgets(line, len, stdin);
        i = strlen(line); if (i>0) if (line[i-1] == 10) line[i-1]=0;

        if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
                fprintf(stderr, "Runtime erreor file %s line %d\n", __FILE__, __LINE__);
                perror("tcsetattr");
                abort();
        }
        return line;
	#else
	    DWORD mode;
	    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
	    GetConsoleMode(console, &mode);
		mode |= (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
	    SetConsoleMode(console, mode );		
        fgets(line, len, stdin);
		puts(""); // Windows ne semble pas faire d'écho au \n entré par l'utilisateur...
        i = strlen(line); if (i>0) if (line[i-1] == 10) line[i-1]=0;	
		return line; /* à finir ... */
	#endif	
}

/********************************************************
 * Les callbacks tels que définis automatiquement depuis
 * le fichier .cli
 * Gestion de la base et des porteurs
 ********************************************************/


/** \brief Callback pour la commande : init { file <STRING:filename> { common parts <INT:common_parts> { secret parts <INT:secret_parts> } } }
 *
 * Avec les paramètres éventuellement donnés, sinon paramètres par défaut
 * Possibilité de ne pas renseigner le nom de fichier, dans ce cas il sera demandé à la sauvegarde (et à NULL en attendant)
 */
cparser_result_t cparser_cmd_init_file_filename_common_parts_common_parts_secret_parts_secret_parts(cparser_context_t *context,
    char **filename_ptr,
    int32_t *common_parts_ptr,
    int32_t *secret_parts_ptr) {

	int tresh_common=2, tresh_secret=3; // valeurs par défaut
	
	t_database **db_ptr = (t_database**)context->cookie[0]; 

	assert(db_ptr != NULL);

	if ( *db_ptr != NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INIT_FILE1) /* "Erreur : une base est déjà ouverte\n"*/ );
		MPM_COLOR_OUTPUT
		printf(msg_get_string(MSG_INIT_FILE2)/*"Il faudrait la fermer d'abord...\n"*/);
		MPM_COLOR_INPUT
		printf("\n");
		return CPARSER_NOT_OK;
	}

	if (common_parts_ptr) tresh_common=*common_parts_ptr;
	if (secret_parts_ptr) tresh_secret=*secret_parts_ptr;

	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_INIT_FILE3)/*"Initialisation d'une nouvelle base\n"*/);
	printf(msg_get_string(MSG_INIT_FILE4)/*"- Nom de fichier : "*/);
	MPM_COLOR_VALUE
	if (filename_ptr) {
		printf("'%s'\n", *filename_ptr);	
	} else {
		printf(msg_get_string(MSG_INIT_FILE5)/*"non fixé (sera demandé à la sauvegarde)\n"*/);
	}

	MPM_COLOR_OUTPUT printf(msg_get_string(MSG_INIT_FILE6)/*"- Seuil pour ouverture 'common' : "*/); MPM_COLOR_VALUE printf("%d\n", tresh_common);
	MPM_COLOR_OUTPUT printf(msg_get_string(MSG_INIT_FILE7)/*"- Seuil pour ouverture 'secret' : "*/); MPM_COLOR_VALUE printf("%d\n", tresh_secret);
	
	if (filename_ptr == NULL) {
		*db_ptr = new t_database(tresh_common, tresh_secret, NULL);
	} else {
		*db_ptr = new t_database(tresh_common, tresh_secret, *filename_ptr);
	}
	cparser_change_current_prompt(context, (*db_ptr)->prompt());
	
	MPM_COLOR_INPUT
	printf("\n");
	return CPARSER_OK;
}


/** \brief Callback pour la commande : save { <STRING:filename> }
 *
 * Nom de fichier éventuellement donné sur la cli, sinon déjà connu dans la base (sinon, erreur)
 */
cparser_result_t cparser_cmd_save_filename(cparser_context_t *context, char **filename_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;

	// Vérifie qu'un base existe en mémoire
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INIT_SAVE1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_INIT_SAVE2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	// Si le nom de fichier n'a pas été fourni, vérifier que la base en a déjà un
	if (filename_ptr == NULL) { // Si le nom de fichier n'a pas été fourni, vérifier que la base en a déjà un
		if (db->filename == NULL) {
			MPM_COLOR_ERROR
			printf(msg_get_string(MSG_INIT_SAVE3)/*"Pas de nom de fichier fourni."*/);
			MPM_COLOR_OUTPUT
			puts(msg_get_string(MSG_INIT_SAVE4)/*" Utilisez donc l'option à la commande 'save'\n"*/);
			MPM_COLOR_INPUT
			printf("\n");		
			return CPARSER_NOT_OK;
		}
	}
	
	// Vérifie si assez de parts ont été distribuées
	int s_total, s_tresh, c_total, c_tresh;
	db->compte_parts_distribuees(&c_total, &s_total);
	db->compte_parts_necessaires(&c_tresh, &s_tresh);
	
	if ((c_total == c_tresh) || (s_total == s_tresh)) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INIT_SAVE5)/*"Attention : "*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_INIT_SAVE6)/*"Le nombre de parts distribuées est juste égal au nombre de parts nécessaires (utilisez 'check' et 'holders show').\n"
			"Vous devriez en distribuer plus, de façon à pouvoir ouvrir la base en cas d'empêchement d'un des porteurs\n"*/);	
	
	} else if ((c_total < c_tresh) || (s_total < s_tresh)) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_ERROR_FEW_DIS_PARTS));
		
		/*"Le nombre de parts distribuées est inférieur au nombre de parts nécessaires (utilisez 'check' et 'holders show').\n"
			"Si vous sauvegardiez la base en l'état, elle ne pourra plus jamais être ouverte.\n"
			"Pour abandonner cette base, utilisez la commande 'quit'");		*/
	
		return CPARSER_NOT_OK;
	}
	
	
	
	// Si un nom de fichier a été fourni, il remplace celui éventuellement existant de la base
	if (filename_ptr != NULL) {
		db->set_filename(*filename_ptr);
	}
	MPM_COLOR_OUTPUT
	db->save();
	MPM_COLOR_INPUT
	cparser_change_current_prompt(context, db->prompt()); // pour tenir compte de l'indicateur de modification qui a disparu
	return CPARSER_OK;
}



/** \brief Callback pour la commande : load <STRING:filename>
 */
cparser_result_t cparser_cmd_load_filename(cparser_context_t *context, char **filename_ptr) {
	t_database *db = *(t_database**)context->cookie[0];

	// Vérifie qu'un base existe en mémoire
	if (db != NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERR_DB_ALREADY)/*"Erreur : une base est déjà ouverte\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_ERR_DB_ALREADY2)/*"Vous devez la fermer d'abord avec 'close'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	// Si le nom de fichier n'a pas été fourni, vérifier que la base en a déjà un
	if (filename_ptr == NULL) { // Si le nom de fichier n'a pas été fourni, vérifier que la base en a déjà un
		if (db->filename == NULL) {
			MPM_COLOR_ERROR
			printf(msg_get_string(MSG_ERR_NO_FILENAME)/*"Erreur : pas de nom de fichier fourni."*/);
			MPM_COLOR_OUTPUT
			puts(msg_get_string(MSG_ERR_NO_FILENAME)/*" Dans ce cas, ce n'est pas une option...\n"*/);
			MPM_COLOR_INPUT
			printf("\n");		
			return CPARSER_NOT_OK;
		}
	}

	// Essaie d'accéder au fichier pour vérifier
	FILE *f;
    f=fopen(*filename_ptr, "r");
    if (f) {
        db=new t_database();
        db->set_filename(*filename_ptr);
        db->status=MPM_LEVEL_NONE; // le constructeur le fixe à INIT car il sert pour les nouvelles BDD
        fclose(f);
		MPM_COLOR_OUTPUT
        printf(msg_get_string(MSG_FIRST_OK)/*"Accès au fichier Ok. Vous devez maintenant ouvrir des parts avec 'try'\n"*/);
		*(t_database**)context->cookie[0] = db;
		cparser_change_current_prompt(context, db->prompt());
		MPM_COLOR_INPUT
		printf("\n");	
		
		return CPARSER_OK;			
    } else {
		MPM_COLOR_ERROR
        printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/);
		MPM_COLOR_OUTPUT
		printf("%s\n\n", strerror(errno)); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
    }
	abort();
}


/** \brief Callback pour la commande : try <STRING:nickname>
 */
cparser_result_t cparser_cmd_try_nickname(cparser_context_t *context,    char **nickname_ptr) { 
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;

	// Vérifie qu'un base existe en mémoire
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_NO_DB)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_ERROR_NO_DB2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	char mdp[256];
	
	MPM_COLOR_INPUT
	printf(msg_get_string(MSG_GIVE_PWD)/*"\tEntrez le mot de passe de '%s' : "*/, *nickname_ptr);
	cli_input_no_echo(mdp, 255);
	
	int apporte_common, apporte_secret;
	int r = db->try_nickname(*nickname_ptr, mdp, &apporte_common, &apporte_secret);
	
	
 
    switch (r) {
		case MPM_TRY_OK:
				MPM_COLOR_OUTPUT
				printf(/*"Ok. %s a apporte des parts %d/%d\n*/ msg_get_string(MSG_TRY_OK), *nickname_ptr, apporte_common, apporte_secret); 
				break;

		case MPM_TRY_NOT_FOUND:
				MPM_COLOR_ERROR printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur :"*/); MPM_COLOR_OUTPUT
				printf(msg_get_string(MSG_TRY_NOK1) /*" Nickname inconnu ou mot de passe erroné.\n"*/);
				break;

		case MPM_TRY_ALREADY_OPENED:
				MPM_COLOR_ERROR printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur :"*/); MPM_COLOR_OUTPUT
				printf(msg_get_string(MSG_TRY_NOK_ALREADY)/*" les parts de %s étaient déjà ouvertes.\n"*/, *nickname_ptr);
				break;

		case MPM_TRY_INCONSISTENT:
				MPM_COLOR_ERROR printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/); MPM_COLOR_OUTPUT
				printf(msg_get_string(MSG_TRY_NOK_INCONSISTENT)/*" incohérence dans la base.\n"*/);
				break;
	
		default:
				abort();
    }

	MPM_COLOR_INPUT
	cparser_change_current_prompt(context, db->prompt()); 
	return CPARSER_OK;
}



/** \brief Callback pour la commande : quit
 */
cparser_result_t cparser_cmd_quit(cparser_context_t *context) {
	return cparser_quit(context->parser);
}


/**
 * \brief Callback pour la commande : check
 * \todo vérifier la position du chunk common
 * \todo vérifier qu'on a distribué assez de parts
 * \todo vérifier les secrets en tire-lire  
 */
cparser_result_t cparser_cmd_check(cparser_context_t *context) {	
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;

	// Vérifie qu'un base existe en mémoire
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	MPM_COLOR_OUTPUT
	switch (db->status) {
		case MPM_LEVEL_INIT : /* Base vide pas encore initialisée */
			printf(msg_get_string(MSG_CHECK3)/*"Base de donnée vierge. Vous devez créer des porteurs avant d'enregistrer\n"*/);
			break;
		case MPM_LEVEL_NONE : /* Base non ouverte, ne peut pas être encore différenciée d'une suite d'octets aléatoires */
			printf(msg_get_string(MSG_CHECK4)/*"Base de donnée fermée, aucun porteur n'a ouvert ses parts. Aucun moyen de distinguer la base de données aléatoires\n"*/);
			break;
		case MPM_LEVEL_FIRST : /* Au moins un utilisateur a été reconnu, mais pas encore de quorum "common" */
			printf(msg_get_string(MSG_CHECK5)/*"Un porteur au moins a ouvert ses parts, mais pas assez pour atteindre le niveau 'common'\n"*/);
			break;
		case MPM_LEVEL_COMMON : /* Base ouverte, on a le quorum "common" */
			printf(msg_get_string(MSG_CHECK6)/*"La base est ouverte au niveau 'common'. Les sercrets restent cachés. Il n'est pas possible de rajouter des porteurs.\n"*/);
			break;
		case MPM_LEVEL_SECRET : 
			printf(msg_get_string(MSG_CHECK7)/*"La base est ouverte y compris au niveau 'secret'. Tout est éditable. Il est possible de rajouter de nouveaux porteurs.\n"*/);
			break;
	}

	if (db->get_status() != MPM_LEVEL_NONE) {
		int c_dist=0, c_necess=0, c_disp=0;
		int s_dist=0, s_necess=0, s_disp=0;
		db->compte_parts_distribuees(&c_dist, &s_dist);
		db->compte_parts_necessaires(&c_necess, &s_necess);
		db->compte_parts_disponibles(&c_disp, &s_disp);

		bool warn_parts = (c_dist<=c_necess) || (s_dist<=s_necess);
		printf(msg_get_string(MSG_CHECK_NBP) /*\nNombre de parts : \n"*/);
		//                                     0123456789012345678901234567890123456789
		printf(msg_get_string(MSG_CHECK_NB1)/*"              Dispo.   Necess.  Distrib.  \n"*/);
		printf(                               "common:   %8d  %8d  %8d  \n", c_disp, c_necess, c_dist);
		printf(                               "secret:   %8d  %8d  %8d  \n", s_disp, s_necess, s_dist);
		
		if (db->get_status() == MPM_LEVEL_FIRST) {
			printf(msg_get_string(MSG_CHECK_WARN_FIRST)/*"Attention : base ouverte au niveau 'first', le décompte des parts distribuées n'est pas complet\n"*/);
		}

		if ((db->get_status() != MPM_LEVEL_FIRST) && warn_parts) {
			MPM_COLOR_ERROR printf(msg_get_string(MSG_CHECK_WARN)/*"\nAttention : "*/);
			MPM_COLOR_OUTPUT 
			puts(msg_get_string(MSG_CHECK_JUST_ENOUGH)/*"Le nombre de parts distribuées est juste égal ou inférieur au nombre de parts nécessaires (utilisez 'show holders').\n"
				"Vous devriez en distribuer plus, de façon à pouvoir ouvrir la base, même en cas d'empêchement d'un des porteurs\n"*/ );
		}
	}

	int c=db->is_changed();
	printf("%s ", ((c)!=0)                       ? msg_get_string(MSG_CHECK_CHANGED1) /*"La base a été modifiée. "*/ :"");
	printf("%s ", ((c&MPM_CHANGED_PASSWORD)!=0)  ?                                      "(pwd) "                     :"");
	printf("%s ", ((c&MPM_CHANGED_SECRET)!=0)    ?                                      "(secrets) "                 :"");	
	printf("%s ", ((c&MPM_CHANGED_HOLDER)!=0)    ?                                      "(holders) "                 :"");
	printf("%s ", ((c&MPM_CHANGED_NEW)!=0)       ?                                      "(new base) "                :"");
	printf("\n\n");

	MPM_COLOR_INPUT
	return CPARSER_OK;
}



/*************************************************************************************
 * Gestion des porteurs 
 *************************************************************************************/

/** \brief Callback pour la commande : new holder <STRING:nickname>
 */
cparser_result_t cparser_cmd_new_holder_nickname(cparser_context_t *context, char **nickname_ptr) { 
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;

	// Vérifie qu'un base existe en mémoire
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INIT_SAVE1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_INIT_SAVE2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	// Vérifie qu'un base existe en mémoire
	if (db->get_status() != MPM_LEVEL_SECRET) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"Vous devez être en niveau 'secret' pour manipuler les porteurs\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	t_holder *p = db->find_holder(*nickname_ptr);
	
	if (p != NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/);
		MPM_COLOR_OUTPUT
		printf(msg_get_string(MSG_NEW_HOLDER_ERR_ALREADY)/*"Ce holder existe déjà, ou ce nickname est déjà utilisé.\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	// Demande le mot de passe pour le nouveau holder
	char mdp1[256];
	char mdp2[256];
	bool pwd_ok=false;
	MPM_COLOR_INPUT
	printf(msg_get_string(MSG_NEW_HOLDER_GIVE_PWD) /*\tDonnez un mot de passe pour ce nouveau porteur : "*/);
	cli_input_no_echo(mdp1, 255);
	printf(msg_get_string(MSG_NEW_HOLDER_CONFIRM_PWD)/*"\tConfirmez le mot de passe : "*/);
	cli_input_no_echo(mdp2, 255);
	if (strcmp(mdp1, mdp2) != 0){
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERR_PWD_CONFIRM)/*"Erreur : confirmation du mot de passe incorrecte."*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	MPM_COLOR_OUTPUT
	p = new t_holder(*nickname_ptr,db);
	db->holders = tdll_append(db->holders, p); db->nb_holders++; ///< \todo créer une fonction d'interface de la classe t_database
	p->set_password(mdp1);
	db->set_changed(MPM_CHANGED_HOLDER);
	printf(msg_get_string(MSG_NEW_HOLDER_OK)/*"\tNouveau porteur (id=%d '%s') créé. Ses parts sont disponibles, et vous pouvez en changer le nombre.\n"*/, p->get_id_holder(), *nickname_ptr);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;
}



/** \brief Callback pour la commande : edit holder <STRING:nickname> password
 */
cparser_result_t cparser_cmd_edit_holder_nickname_password(cparser_context_t *context, char **nickname_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if (( db->get_status() != MPM_LEVEL_INIT) && (db->get_status() != MPM_LEVEL_SECRET) ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : \n"*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"La base doit être ouverte au niveau 'secret' pour pouvoir gérer les porteurs.\n"*/); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;			
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	t_holder *p;
	if ( (p = db->find_holder(*nickname_ptr)) == NULL ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}	

	char mdp1[256];
	char mdp2[256];
	bool pwd_ok=false;
	
	MPM_COLOR_INPUT
	printf(msg_get_string(MSG_NEW_HOLDER_GIVE_PWD)/*"\tEntrez le nouveau mot de passe : "*/);
	cli_input_no_echo(mdp1, 255);

	printf(msg_get_string(MSG_NEW_HOLDER_CONFIRM_PWD)/*"\tEntrez le nouveau mot de passe à nouveau : "*/);
	cli_input_no_echo(mdp2, 255);

	if (strcmp(mdp1, mdp2) != 0) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERR_PWD_CONFIRM)/*"Erreur : confirmation du mot de passe incorrecte."*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	p->set_password(mdp1);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;	
}

 



/** \brief Callback pour la commande : edit holder <STRING:nickname> common parts <INT:common_parts>
 */
cparser_result_t cparser_cmd_edit_holder_nickname_common_parts_common_parts(cparser_context_t *context, char **nickname_ptr, int32_t *common_parts_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if (( db->get_status() != MPM_LEVEL_INIT) && (db->get_status() != MPM_LEVEL_SECRET) ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : \n"*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"La base doit être ouverte au niveau 'secret' pour pouvoir gérer les porteurs.\n"*/); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;			
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	t_holder *p;
	if ( (p = db->find_holder(*nickname_ptr)) == NULL ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}	

	if (p->set_nb_common(*common_parts_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_FAIL)/*"Echec \n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	
	}
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	printf("\n");
	return CPARSER_OK;

}



/** \brief Callback pour la commande : edit holder <STRING:nickname> secret parts <INT:secret_parts>
 */
cparser_result_t cparser_cmd_edit_holder_nickname_secret_parts_secret_parts(cparser_context_t *context, char **nickname_ptr, int32_t *secret_parts_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if (( db->get_status() != MPM_LEVEL_INIT) && (db->get_status() != MPM_LEVEL_SECRET) ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : \n"*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"La base doit être ouverte au niveau 'secret' pour pouvoir gérer les porteurs.\n"*/); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;			
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	t_holder *p;
	if ( (p = db->find_holder(*nickname_ptr)) == NULL ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (p->set_nb_secret(*secret_parts_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_FAIL)/*"Echec \n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}	

	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	printf("\n");
	return CPARSER_OK;
}


/** \brief Callback pour la commande : edit holder <STRING:nickname> email <STRING:email>
 */
cparser_result_t cparser_cmd_edit_holder_nickname_email_email(cparser_context_t *context, char **nickname_ptr, char **email_ptr) { 
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if (( db->get_status() != MPM_LEVEL_INIT) && (db->get_status() != MPM_LEVEL_SECRET) ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : \n"*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"La base doit être ouverte au niveau 'secret' pour pouvoir gérer les porteurs.\n"*/); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;			
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	t_holder *p;
	if ( (p = db->find_holder(*nickname_ptr)) == NULL ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (email_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_EMAIL)/*"Adresse e-mail invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}
	p->set_email(*email_ptr);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	printf("\n");	
	return CPARSER_OK;
}


/** \brief Callback pour la commande : show holders
 */
cparser_result_t cparser_cmd_show_holders(cparser_context_t *context) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;

	// Vérifie qu'un base existe en mémoire
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Pas de base de secret chargée\n"*/);
		MPM_COLOR_OUTPUT
		puts(msg_get_string(MSG_CHECK2)/*"Vous devriez en charger une avec 'load' ou en créer une avec 'init'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

    /*GList*/ tdllist *gl;
    char *em;

    int nclosed=0;
    gl = db->holders;
    MPM_COLOR_OUTPUT
    if (gl) {
            printf(msg_get_string(MSG_SHOW_HOLD1)/*"Porteurs déclarés dont les parts sont débloquées (nickname / nb parts common / nb parts secret / email):\n"*/);
    } else {
            printf(msg_get_string(MSG_SHOW_HOLD2)/*"Aucun porteur n'est encore connu dans cette base\n"*/);
    }

    MPM_COLOR_VALUE
    while (gl) {
            if ((((t_holder*)gl->data)->chunk_status == HOLDER_CHUNK_STATUS_OPEN) || (((t_holder*)gl->data)->chunk_status == HOLDER_CHUNK_STATUS_NONE)) {
                    
                    printf("\t%s ",  ((t_holder*)gl->data)->nickname);
                    printf("%d / %d ",  ((t_holder*)gl->data)->get_nb_common(), ((t_holder*)gl->data)->get_nb_secret());
                    
                    em=((t_holder*)gl->data)->get_email(); 
                    if (em) { printf("%s",em); }
                    printf("\n");
            } else if (((t_holder*)gl->data)->chunk_status == HOLDER_CHUNK_STATUS_CLOSED)  {
                    nclosed++;
            } else {
                    #ifdef DEBUG
                    debug_printf(0, (char*)"%s() incohérence chunk_status\n",(char*)__func__);
                    #endif          
            }
            #ifdef DEBUG
            unsigned char * chunk=((t_holder*)gl->data)->chunk;
            debug_printf(0, (char*)"%s() %s file index=%d chunk_status=%d id=%d\n",(char*)__func__,((t_holder*)gl->data)->nickname, ((t_holder*)gl->data)->file_index, ((t_holder*)gl->data)->chunk_status, ((t_holder*)gl->data)->id_holder);
            debug_printf(0, (char*)"%s() chunk=%lx partie chiffrée=%lx\n", (char*)__func__, *(uint64_t*) chunk, *(uint64_t*) (chunk+CHUNK_HOLDER_AES_OFFSET));              
            #endif

            gl=gl->next;
    }
    if ((db->status == MPM_LEVEL_INIT) || (db->status == MPM_LEVEL_NONE)) {
            MPM_COLOR_OUTPUT printf(msg_get_string(MSG_SHOW_HOLD3)/*"Nombre de holders encore inconnu dans cet état\n"*/);
    }

    if (nclosed) {
            MPM_COLOR_OUTPUT printf(msg_get_string(MSG_SHOW_HOLD4)/*"Porteurs n'ayant pas débloqué leurs parts :\n"*/); MPM_COLOR_VALUE
            gl = db->holders;
            while (gl) {
                    if (((t_holder*)gl->data)->chunk_status == HOLDER_CHUNK_STATUS_CLOSED) {
                            printf("\t%s ",  ((t_holder*)gl->data)->nickname);
                            printf("%d / %d \n",  ((t_holder*)gl->data)->get_nb_common(), ((t_holder*)gl->data)->get_nb_secret());
                    }
                    gl=gl->next;
            }
            printf("\n");
    }
    if ((db->status == MPM_LEVEL_FIRST) || (db->status == MPM_LEVEL_COMMON) || (db->status == MPM_LEVEL_SECRET)) {
            MPM_COLOR_OUTPUT printf(msg_get_string(MSG_SHOW_HOLD5)/*"Nombre total de holders détecté : "*/);
            MPM_COLOR_VALUE printf("%d\n", db->nb_holders);
    }
	MPM_COLOR_INPUT
	return CPARSER_OK;
}

/** \brief Callback pour la commande : delete holder <STRING:nickname>
 */
cparser_result_t cparser_cmd_delete_holder_nickname(cparser_context_t *context, char **nickname_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_holder *p;

	if (( db->get_status() != MPM_LEVEL_INIT) && (db->get_status() != MPM_LEVEL_SECRET) ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : \n"*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_NEW_HOLDER_NOT_SECRET)/*"La base doit être ouverte au niveau 'secret' pour pouvoir gérer les porteurs.\n"*/); 
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;			
	}
	
	if (nickname_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if ( (p = db->find_holder(*nickname_ptr)) == NULL ) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INV_NICKNAME)/*"Nickname invalide\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}	
	
	int c_tresh=0, s_tresh=0; // Le seuil des shamir
	int c_total=0, s_total=0; // Nombre total de parts distribuées
	int c_parts=0, s_parts=0; // Nombre de part de l'utilisateur qu'on voudrait supprimer
    db->compte_parts_disponibles(&c_total, &s_total);
	db->compte_parts_necessaires(&c_tresh, &s_tresh);
	p->compte_parts_disponibles(&c_parts, &s_parts);
	
    #ifdef DEBUG
    debug_printf(0, "%s() %s:%d %s apporte %d/%d seuils à %d/%d\n", __func__, __FILE__, __LINE__, *nickname_ptr, c_parts, s_parts, c_tresh, s_tresh);
    #endif
	
	c_total -= c_parts; s_total-=s_parts;
		
	if ((c_total < c_tresh)||(s_total < s_tresh)) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_DEL_HOLD1)/*"Suppression impossible : "*/);
		MPM_COLOR_OUTPUT puts(msg_get_string(MSG_DEL_HOLD2)/*"Vous devez distribuer plus de parts au préalable.\nUtilisez les commandes 'check' et 'holders show' pour voir les parts distribuées\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	// TODO : mériterait une méthode dans t_database::
	//db->holders = g_list_remove(db->holders, p); // Supprime le lien g_list
	db->holders = tdll_remove(db->holders, p); // Supprime le lien g_list
	delete p; // supprime l'objet lui-même
	assert(db->nb_holders >0);
	db->nb_holders--;
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_OUTPUT puts(msg_get_string(MSG_DEL_HOLD_OK)/*"Suppression ok\n"*/);
	MPM_COLOR_INPUT
	return CPARSER_OK;
}





/********************************************************
 * Gestion des secrets
 ********************************************************/


/** \brief Callback pour la commande : pwd
 */
cparser_result_t cparser_cmd_pwd(cparser_context_t *context) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* f = db->get_current_folder();
	MPM_COLOR_OUTPUT printf(msg_get_string(MSG_CWD)/*"chemin actuel :"*/);
	MPM_COLOR_VALUE  printf(f->get_title_path()); printf("\n");
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : cd <STRING:id>
 * \note le paramètre est une chaine pour prendre en compte le '..'
 */
cparser_result_t cparser_cmd_cd_id(cparser_context_t *context, char **id_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();
	t_secret_folder *nf;
	
	bool succes = false;

	printf(msg_get_string(MSG_CHDIR)/*"changement de répertoire vers '%s'\n"*/, *id_ptr);

	if (strcmp(*id_ptr, "..") == 0) {
		nf = cf->get_parent_folder(); 
		succes = (nf != NULL);
	} else {
		if (strlen(*id_ptr)<10) { // un ID > 1 milliard est censé être impossible
			int id;	
			sscanf(*id_ptr, "%d", &id);
			nf = cf->get_sub_folder_by_id(id);
			succes = (nf != NULL);
		} 
	}

	if (succes == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"Erreur : id invalide\n"*/);
	} else {
		db->set_current_folder(nf);
	}
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : ls
 */
cparser_result_t cparser_cmd_ls(cparser_context_t *context) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	//t_secret_folder *cf = (t_secret_folder*)context->cookie[1];	
	t_secret_folder* cf = db->get_current_folder();
	
	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_LS1)/*"Dossier courant : [%d] %s\n\n"*/, cf->get_id(), cf->get_title_path());

	// Affichage des sous dossiers
	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_LS2)/*"Sous-dossiers :\n"*/);

	for (/*GList*/ tdllist* gl=cf->get_sub_folders(); gl; gl=gl->next) {
		printf("[%d] %s\n", ((t_secret_folder*)gl->data)->get_id(), ((t_secret_folder*)gl->data)->get_title());
	}
	printf("\n");	
	
	// Affichage des secrets
	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_LS3)/*"Entrées de secrets :\n"*/);

	for (/*GList*/ tdllist* gl=cf->get_secrets(); gl; gl=gl->next) {
		printf("[%d] %s\n", ((t_secret_item*)gl->data)->get_id(), ((t_secret_item*)gl->data)->get_title());
	}
	printf("\n");
	
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : new folder
 */
cparser_result_t cparser_cmd_new_folder(cparser_context_t *context){
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	char nom_dossier[256];
	t_secret_folder* cf = db->get_current_folder();

	MPM_COLOR_OUTPUT printf(msg_get_string(MSG_NEWFOLD1)/*"Titre du nouveau dossier ? "*/);
	MPM_COLOR_VALUE  cli_input(nom_dossier, 255);

	t_secret_folder *nf = new t_secret_folder(cf, nom_dossier, db->get_free_id(), db); // dossier nouveau

	cf->add_sub_folder(nf);
	db->set_current_folder(nf);

	printf(msg_get_string(MSG_NEWFOLD2)/*"ID du nouveau dossier = %d\n"*/, nf->get_id());

	MPM_COLOR_INPUT
	cparser_change_current_prompt(context, db->prompt());
	return CPARSER_OK;
}


/** \brief Callback pour la commande : new secret
 */
cparser_result_t cparser_cmd_new_secret(cparser_context_t *context){
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	//t_secret_folder* cf = (t_secret_folder*)context->cookie[1]; // dossier courant
	t_secret_folder* cf = db->get_current_folder();
	char title[256];

	uint32_t id=db->get_free_id();
	MPM_COLOR_INPUT
	printf(msg_get_string(MSG_NEW_SEC1)/*"Donnez un titre à ce secret : "*/);
	MPM_COLOR_VALUE
	cli_input(title,255);

	t_secret_item* ns = new t_secret_item(cf, title, id);
	cf->add_secret_item(ns);

	MPM_COLOR_INPUT
	printf(msg_get_string(MSG_NEW_SEC2)/*"id du nouveau secret : "*/);
	MPM_COLOR_VALUE
	printf("%d\n", id);

	MPM_COLOR_INPUT
	cparser_change_current_prompt(context, db->prompt());
	printf("\n");
	return CPARSER_OK;
}


/** \brief Callback pour la commande : edit secret <INT:id> update { field <STRING:field_name> }
 */
cparser_result_t cparser_cmd_edit_secret_id_update_field_field_name(cparser_context_t *context, int32_t *id_ptr, char **field_name_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();
	if (id_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (field_name_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_EDSEC1)/*"Erreur : dialogue de revue de tous les champs pas encore implémenté\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (*field_name_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_EDSEC2)/*"Nom de champ incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	char* v = s->get_field_value(*field_name_ptr);
	if (v) {
		MPM_COLOR_INPUT
		printf(msg_get_string(MSG_EDSEC3)/*"Valeur actuel du champ [%s] : "*/, *field_name_ptr);
		MPM_COLOR_VALUE
		printf("%s\n", v);
	} else {
		MPM_COLOR_INPUT
		printf(msg_get_string(MSG_EDSEC4)/*"Nouveau champ.\n"*/);
		
	}

	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_EDSEC5)/*"Entrez la nouvelle valeur de ce champ : "*/);
	MPM_COLOR_VALUE
	v=(char*)alloca(256);
	cli_input(v, 255);

	s->update_field(*field_name_ptr, v);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;	
}


/** \brief Callback pour la commande : edit secret <INT:id> delete field <STRING:field_name>
 */
cparser_result_t cparser_cmd_edit_secret_id_delete_field_field_name(cparser_context_t *context, int32_t *id_ptr, char **field_name_ptr) {

	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();	
	if (id_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	if (s->field_exist(*field_name_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_SEC_DEL_FIELD)/*"Champ inexistant\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}

	s->delete_field(*field_name_ptr);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : edit secret <INT:id> title
 */
cparser_result_t cparser_cmd_edit_secret_id_title(cparser_context_t *context, int32_t *id_ptr){
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();
	if (id_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	MPM_COLOR_OUTPUT
	printf(msg_get_string(MSG_ED_SEC_TITLE)/*"Titre actuel [%d] : "*/, *id_ptr);
	MPM_COLOR_VALUE
	printf("%s\n", s->get_title());
	
	MPM_COLOR_OUTPUT
	char *v=(char*)alloca(256);
	printf(msg_get_string(MSG_ED_SEC_TITLE2)/*"Entrez un nouveau titre : "*/);
	MPM_COLOR_VALUE cli_input(v, 255);
	s->set_title(v);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : delete <INT:id> { <LIST:force:force> }
 *  \note suppression d'un dossier ou d'un secret, selon l'ID
 */
cparser_result_t cparser_cmd_delete_id_force(cparser_context_t *context, int32_t *id_ptr, char **force_ptr)
{
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	//t_secret_folder* cf = (t_secret_folder*)context->cookie[1]; // dossier courant
	t_secret_folder* cf = db->get_current_folder();	

	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	t_secret_folder* f = cf->get_sub_folder_by_id(*id_ptr);

	bool force=false;
	if (force_ptr) {
		force = (strcmp(*force_ptr, "force") == 0);
	}

	if (s != NULL) {
		// suppression d'un secret
		if (!force) {
			MPM_COLOR_OUTPUT printf(msg_get_string(MSG_DELETE_ID)/*" Suppression de '%s' : confirmez (o/n) "*/, s->get_title());
			char* v=(char*)alloca(8);
			MPM_COLOR_VALUE cli_input(v, 5);
			if (strcmp(v, "o") != 0) {
				printf(msg_get_string(MSG_DELETE_ID4)/*" - annulé\n"*/);
				MPM_COLOR_INPUT	
				return CPARSER_NOT_OK;
			}
		}
		cf->delete_secret_item(*id_ptr);	
	} else if (f != NULL) {
		// suppression d'un dossier
		if (f->is_empty() || (force)) {
			cf->delete_sub_folder(*id_ptr);
			f=NULL;			
		} else {
			MPM_COLOR_ERROR  printf(msg_get_string(MSG_DELETE_ID2)/*"Erreur : dossier non vide."*/);
			MPM_COLOR_OUTPUT printf(msg_get_string(MSG_DELETE_ID3)/*" Utilisez 'force'\n"*/);
			MPM_COLOR_INPUT  printf("\n");		
			return CPARSER_NOT_OK;
		}
		
	} else {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;
}


/** \brief Callback pour la commande : show secret <INT:id>
 */
cparser_result_t cparser_cmd_show_secret_id(cparser_context_t *context, int *id_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	//t_secret_folder* cf = (t_secret_folder*)context->cookie[1];
	t_secret_folder* cf = db->get_current_folder();	
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	char *v;
	MPM_COLOR_OUTPUT  
	printf(msg_get_string(MSG_SHSEC1)/*"Secret ["*/); MPM_COLOR_VALUE printf("%d", *id_ptr); MPM_COLOR_OUTPUT printf("] : "); MPM_COLOR_VALUE printf("%s\n",s->get_title());
	MPM_COLOR_OUTPUT printf(msg_get_string(MSG_SHSEC2)/*"Contenu :\n"*/);
	for (/*GList*/ tdllist* f=s->get_fields(); f; f=f->next) {
		MPM_COLOR_OUTPUT printf("\t["); MPM_COLOR_VALUE 
		printf(((t_secret_field*)f->data)->get_field_name()); 
		MPM_COLOR_OUTPUT printf("] : "); MPM_COLOR_VALUE 
		v=((t_secret_field*)f->data)->get_value();
		MPM_ANSI_TERM_BOXED
		if (v==NULL) {
			MPM_COLOR_VALUE
			printf(msg_get_string(MSG_EMPTY)/*"(vide)\n"*/);
		} else if ( ((t_secret_field*)f->data)->is_secret() ) {
			MPM_COLOR_SVALUE
			if (db->get_status()==MPM_LEVEL_SECRET) {
				printf("%s\n",((t_secret_field*)f->data)->get_value());
			} else {
				printf(msg_get_string(MSG_SHSEC3)/*"*base pas ouverte au niveau 'secret'*\n"*/);
			}
		} else {
			MPM_COLOR_VALUE 
			printf("%s\n",((t_secret_field*)f->data)->get_value());
		}
		MPM_ANSI_TERM_NOBOX
		
	}

	// MPM_COLOR_OUPUT
	// MPM_COLOR_VALUE
	
	MPM_COLOR_INPUT
	return CPARSER_OK;
}




/** \brief Callback pour la commande : edit secret <INT:id> generate field <STRING:field_name> { length <INT:length> }
 */
cparser_result_t cparser_cmd_edit_secret_id_generate_field_field_name_length_length(cparser_context_t *context, int32_t *id_ptr, char **field_name_ptr, int32_t *length_ptr) {

	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	
	if (db == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_CHECK1)/*"Erreur : Pas de base ouverte\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	t_secret_folder* cf = db->get_current_folder();
	
	if (id_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (*field_name_ptr == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_FIELD)/*"Nom de champ incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;
	}

	if (s->field_exist(*field_name_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_FIELD)/*"Champ inexistant\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	int length=22; // entropie équivalente 128 bits

	if (length_ptr != NULL) length = *length_ptr;
	
	char* pwd = (char*) alloca(length+4);
	generate_password(pwd, length);
	s->update_field(*field_name_ptr, pwd);
	cparser_change_current_prompt(context, db->prompt());
	MPM_COLOR_INPUT
	return CPARSER_OK;
}

/** \brief Callback pour la commande :  edit secret <INT:id> secret <STRING:field_name>
 * Rend secret un champ actuellement disponible en niveau 'common'
 */
cparser_result_t cparser_cmd_edit_secret_id_secret_field_name(cparser_context_t *context, int32_t *id_ptr, char **field_name_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);
	
	if (db->get_status() != MPM_LEVEL_SECRET) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/); MPM_COLOR_OUTPUT 
		printf(msg_get_string(MSG_SHSEC3)/*"action possible uniquement sur une base ouverte en niveau 'secret'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}
	
	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	if (s->field_exist(*field_name_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_FIELD)/*"Champ inexistant\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	s->set_field_secret(*field_name_ptr);
	cparser_change_current_prompt(context, db->prompt());
	return CPARSER_OK;
}


/** \brief Callback pour la commande : edit secret <INT:id> common <STRING:field_name>
 * Rend accessible en niveau 'common' un champ réservé avant au niveau 'secret'
 */
cparser_result_t cparser_cmd_edit_secret_id_common_field_name(cparser_context_t *context, int32_t *id_ptr, char **field_name_ptr) {
	t_database **db_ptr = (t_database**)context->cookie[0];
	t_database *db= *db_ptr;
	t_secret_folder* cf = db->get_current_folder();
	t_secret_item* s = cf->get_secret_by_id(*id_ptr);

	if (db->get_status() != MPM_LEVEL_SECRET) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_ERROR_SCOLON)/*"Erreur : "*/); MPM_COLOR_OUTPUT 
		printf(msg_get_string(MSG_SHSEC3)/*"action possible uniquement sur une base ouverte en niveau 'secret'\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;	
	}

	if (s == NULL) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_ID)/*"ID incorrect\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}
	
	if (s->field_exist(*field_name_ptr) == false) {
		MPM_COLOR_ERROR
		printf(msg_get_string(MSG_INVALID_FIELD)/*"Champ inexistant\n"*/);
		MPM_COLOR_INPUT
		printf("\n");		
		return CPARSER_NOT_OK;		
	}

	s->set_field_common(*field_name_ptr);
	return CPARSER_OK;
}
