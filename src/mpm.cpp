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


#include <string.h>
#include <stdio.h>

#include <cparser.h>
#include "cparser_tree.h"
#include "mpm.h"


char **program_env; /* used for launchers, in execve() */



int main(int argc, char *argv[], char *env[]) {
	cparser_t parser;

	program_env = env; /* save this for calls to execve in launchers */

	#if defined(DEBUG) && defined(__linux__)
	mcheck(NULL);
	#endif

	#ifdef DEBUG
	debug_init("debug.out",0);
	#endif
		
	t_database *db = NULL;

	random_init();




	// Répérage de la langue qu'on doit utiliser
	char *envLANG = NULL;
	#ifdef __linux__
	envLANG = getenv("LANG");
	#endif
	
	#ifdef _WIN32
	// A faire... A priori, GetLocaleInfoEx() renvoie des codes en hexa, pas une chaine genre fr-FR
	#endif
	
	
	if (envLANG==NULL) envLANG=(char*)"en";
	for (int i=0; i<MSG_NB_LANG ;i++) {
		if (strncmp(msg_codes_lang[i], envLANG, 2) == 0) {
			msg_current_lang = i;
		}
	}	

	// Vérifier si on peut utiliser les codes ansi et mettre à jour cli_use_ansi en conséquence
	// [...] à faire, peut être en mettant une fonction de détection dans cli_callbacks.c
	#ifdef _WIN32
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
	SetConsoleMode(hOut, dwMode);
	cli_use_ansi = 1;
	#endif
	

	
	// Déchiffrement des messages internationalisés
	//cw_aes_cbc((unsigned char *)msg_data, MSG_DATA_LEN, (unsigned char*)"0123456789abcdef0123456789abcdef", (unsigned char*)"0123456789abcdef", 0);
	if (argc == 2) {
		FILE *f;
		f=fopen(argv[1], "r+b"); // ouvre le fichier pour voir si il existe
		if (f) {
			fclose(f);
			db=new t_database();
			db->set_filename(argv[1]);
			db->status=MPM_LEVEL_NONE; // le constructeur le fixe à INIT car il sert pour les nouvelles BDD
		} else {
			printf(msg_get_string(MSG_ERREUR_OPEN_FILE) /* "Erreur d'accès au fichier %s\n\n" */, strerror(errno)); 
			abort();
		}
	}

	memset(&parser, 0, sizeof(parser));
	parser.cfg.root = &cparser_root; // Celui défini dans le fichier précompilé par le script
	parser.cfg.ch_complete = '\t';
	parser.cfg.ch_erase = '\b';
	parser.cfg.ch_del = 127;
	parser.cfg.ch_help = '?';
	if (db == NULL) {
		strncpy(parser.cfg.prompt, "(none) ", CPARSER_MAX_PROMPT);
	} else 	{
		strncpy(parser.cfg.prompt, db->prompt(), CPARSER_MAX_PROMPT);
	}
	parser.cfg.flags = 0; // le seul flag qui semble exister est pour le debug
	parser.cfg.fd = STDOUT_FILENO;
    cparser_io_config(&parser);

    if (CPARSER_OK != cparser_init(&parser.cfg, &parser)) {
        printf("Fail to initialize parser.\n");
        return -1;
    }

	cparser_set_root_context(&parser, &db); // pour fixer le cookie du level root
	
	cli_color_white_bg(); puts("");
	cparser_run(&parser);

	random_deinit();
	cli_ansi_reset();
	puts("\n\n");
	return 0;
}

