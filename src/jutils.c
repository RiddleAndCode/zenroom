/*  Jaromil's utility collection
 *
 *  (c) Copyright 2001-2019 Denis Rojo <jaromil@dyne.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Public License as published 
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <zenroom.h>
#include <zen_error.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

// ANSI colors for terminal
const char* ANSI_RED     = "\x1b[1;31m";
const char* ANSI_GREEN   = "\x1b[1;32m";
const char* ANSI_YELLOW  = "\x1b[1;33m";
const char* ANSI_BLUE    = "\x1b[1;34m";
const char* ANSI_MAGENTA = "\x1b[35m";
const char* ANSI_CYAN    = "\x1b[36m";
const char* ANSI_RESET   = "\x1b[0m";

#define MAX_DEBUG 2
// #define MAX_STRING 1024
#define FUNC 2 /* se il debug level e' questo
		  ci sono le funzioni chiamate */
#define WARN 1 /* ... blkbblbl */

char msg[MAX_STRING];

extern zenroom_t *Z;

static int verbosity = 1;
void set_debug(int lev) {
  lev = lev<0 ? 0 : lev;
  lev = lev>MAX_DEBUG ? MAX_DEBUG : lev;
  verbosity = lev;
}

static int color = 0;
void set_color(int on) { color = on; }

int get_debug() {
  return(verbosity);
}

static void _printf(char *pfx, char *msg) {
	if(!pfx) return;
	if(!msg) return;
#ifdef __ANDROID__
	__android_log_print(ANDROID_LOG_VERBOSE, "KZK", "%s -- %s", pfx, msg);
#endif
	if(Z)
		if(Z->stderr_buf) {
			char *err = Z->stderr_buf;
			size_t len = strlen(msg);
			snprintf(err+Z->stderr_pos,
			         Z->stderr_len-Z->stderr_pos,
			         "%s %s\n", pfx,msg);
			Z->stderr_pos+=len+5;
			return;
		}
	// fallback in any case
	if(color) {
		const char *col = ANSI_RESET;
		switch(pfx[1]) {
		case '!': col = ANSI_RED;    break;
		case 'F': col = ANSI_BLUE;   break; 
		case 'W': col = ANSI_YELLOW; break;
		case '*': col = ANSI_GREEN;  break;
		}
		fprintf(stderr,"%s%s%s %s\n",col,pfx,ANSI_RESET,msg);
	} else
		fprintf(stderr,"%s %s\n",pfx,msg);
}

// static void _printline(zenroom_t *Z, lua_State *L) {
// 	if(!Z || !L) return;
// 	lua_Debug ar;
// 	if(lua_getstack(L, 1, &ar) && lua_getinfo(L, "nSl", &ar)) {
// 		char err[MAX_STRING];
// 		snprintf(err,MAX_STRING-1,"%s:%u: ERROR",
// 		         ar.short_src, ar.currentline);
// 		_printf(Z,"[!]",err);
// 	} else
// 		_printf(Z,"[!]","[UKNOWN STACK]:?: ERROR");
// }

void notice(lua_State *L, const char *format, ...) {
	(void)L;
  va_list arg;
  va_start(arg, format);
  vsnprintf(msg, MAX_STRING, format, arg);
  _printf("[*]", msg);
  va_end(arg);
}

void func(void *L, const char *format, ...) {
	(void)L;
  if(verbosity>=FUNC) {
    va_list arg;
    va_start(arg, format);
    vsnprintf(msg, MAX_STRING, format, arg);
    _printf("[F]", msg);
    va_end(arg);
  }
}

void error(lua_State *L, const char *format, ...) {
	(void)L;
  va_list arg;
  va_start(arg, format);
  vsnprintf(msg, MAX_STRING, format, arg);
  _printf("[!]", msg);
  va_end(arg);
  if(Z) Z->errorlevel = 3;
  // exit(1); // calls teardown (signal 11) TODO: check if OK with seccomp
}

void act(lua_State *L, const char *format, ...) {
	(void)L;
  va_list arg;
  va_start(arg, format);
  
  vsnprintf(msg, MAX_STRING, format, arg);
  _printf(" . ", msg);
  va_end(arg);
}

void warning(lua_State *L, const char *format, ...) {
	(void)L;
  if(verbosity>=WARN) {
    va_list arg;
    va_start(arg, format);
    vsnprintf(msg, MAX_STRING, format, arg);
    _printf("[W]", msg);
    va_end(arg);
    if(Z) Z->errorlevel = 2;
  }
}


