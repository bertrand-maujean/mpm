/**
 * \file     cparser_io_unix.c
 * \brief    Unix-specific parser I/O routines
 * \version  \verbatim $Id: cparser_io_unix.c 159 2011-10-29 09:29:58Z henry $ \endverbatim
 */
/*
 * Copyright (c) 2008-2009, 2011, Henry Kwok
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the project nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY HENRY KWOK ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL HENRY KWOK BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
//#include <termios.h>
//#include <unistd.h>
#include <string.h>
#include <windows.h>
#include "cparser.h"
#include "cparser_io.h"
#include "cparser_priv.h"

#define CTRL_A (1)
#define CTRL_E (5)
#define CTRL_N (14)
#define CTRL_P (16)

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

/**
 * \brief    Enable/disable canonical mode.
 * \details  Note that this call must be made first with enable=0.
 *
 * \param    parser Pointer to the parser.
 * \param    enable 1 to enable; 0 to disable.
 */
static void
cparser_term_set_canonical (cparser_t *parser, int enable)
{
    DWORD mode;
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);

	static int old_term_set = 0;
	static DWORD old_term_mode = 0;
	
	if (!VALID_PARSER(parser)) return;
	
    GetConsoleMode(console, &mode);
	
	if (enable) {
		assert(old_term_set);
		SetConsoleMode(console, old_term_mode);
		old_term_set =0;
	} else {
		old_term_mode = mode;
		old_term_set = 1;
		SetConsoleMode(console, mode & ~(ENABLE_LINE_INPUT));	
	}
}

/*
static void
cparser_win_getch (cparser_t *parser, int *ch, cparser_char_t *type)
{
    assert(VALID_PARSER(parser) && ch && type);
    *type = CPARSER_CHAR_UNKNOWN;
    *ch = getchar();
	if (*ch == 13) {
		printf("CRLFconv");
		*ch=getchar();
		//*ch==10;
	}
    if ('' == *ch) {
        *ch = getchar();
        if ('[' == *ch) {
            *ch = getchar();
            switch (*ch) {
                case 'A':
                    *type = CPARSER_CHAR_UP_ARROW;
                    break;
                case 'B':
                    *type = CPARSER_CHAR_DOWN_ARROW;
                    break;
                case 'C':
                    *type = CPARSER_CHAR_RIGHT_ARROW;
                    break;
                case 'D':
                    *type = CPARSER_CHAR_LEFT_ARROW;
                    break;
            }
        }
    } else if (isalnum(*ch) || ('\n' == *ch) ||
               ispunct(*ch) || (' ' == *ch) ||
               (*ch == parser->cfg.ch_erase) ||
               (*ch == parser->cfg.ch_del) ||
               (*ch == parser->cfg.ch_help) ||
               (*ch == parser->cfg.ch_complete)) {
        *type = CPARSER_CHAR_REGULAR;
    }
}

*/

static void
cparser_win_getch (cparser_t *parser, int *ch, cparser_char_t *type)
{
    assert(VALID_PARSER(parser) && ch && type);
    *type = CPARSER_CHAR_UNKNOWN;
	
	int c = getch();
	int c2 = 0;
	if (kbhit()) c2=getch();
	
	if (((c == 0x0d) || (c==0x0a)) && (c2 == 0)) {
		*ch = 10;
		*type = CPARSER_CHAR_REGULAR;
		return;
	}
	
	if ((c==0)||(c==0xe0)) {
		switch(c2) {
			case 'H' : *type = CPARSER_CHAR_UP_ARROW;    *ch = 'A'; break;
			case 'P' : *type = CPARSER_CHAR_DOWN_ARROW;  *ch = 'B'; break;
			case 'K' : *type = CPARSER_CHAR_LEFT_ARROW;  *ch = 'D'; break;
			case 'M' : *type = CPARSER_CHAR_RIGHT_ARROW; *ch = 'C'; break;			
		}
		return;
	}
	
	if (isalnum(c) || ispunct(c) || (c == ' ') || (c == '\n') ||
			   (c == parser->cfg.ch_erase) ||
               (c == parser->cfg.ch_del) ||
               (c == parser->cfg.ch_help) ||
               (c == parser->cfg.ch_complete)) {
		*ch = c;
		*type = CPARSER_CHAR_REGULAR;
		return;
	}

}


static void
cparser_win_printc (const cparser_t *parser, const char ch)
{
    ssize_t wsize;
    assert(parser);
    wsize = write(parser->cfg.fd, &ch, 1);
    assert((0 <= wsize) || (-1 == parser->cfg.fd));
}

static void
cparser_win_prints (const cparser_t *parser, const char *s)
{
    ssize_t wsize;
    assert(parser);
    if (s) {
        wsize = write(parser->cfg.fd, s, strlen(s));
        assert((0 <= wsize) || (-1 == parser->cfg.fd));
    }
}

static void 
cparser_win_io_init (cparser_t *parser)
{
    cparser_term_set_canonical(parser, 0);
}

static void
cparser_win_io_cleanup (cparser_t *parser)
{
    cparser_term_set_canonical(parser, 1);
}

void
cparser_io_config (cparser_t *parser)
{
    assert(parser);
    parser->cfg.io_init    = cparser_win_io_init;
    parser->cfg.io_cleanup = cparser_win_io_cleanup;
    parser->cfg.getch      = cparser_win_getch;
    parser->cfg.printc     = cparser_win_printc;
    parser->cfg.prints     = cparser_win_prints;
}
