/*  Lua based DECODE VM
 *
 *  (c) Copyright 2017 Dyne.org foundation
 *  designed, written and maintained by Denis Roio <jaromil@dyne.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Public License as published
 * by the Free Software Foundation; either version 3 of the License,
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jutils.h>

#include <luasandbox.h>
#include <luasandbox/util/util.h>
#include <luasandbox/lauxlib.h>

#define CONF "decode-exec.conf"

extern const struct luaL_Reg luanachalib;

// from timing.c
// extern int set_hook(lua_State *L);

// void log_debug(lua_State *l, lua_Debug *d) {
// 	error("%s\n%s\n%s",d->name, d->namewhat, d->short_src);
// }

void logger(void *context, const char *component,
                   int level, const char *fmt, ...) {
	(void)context;
	va_list args;
	// fprintf(stderr, "%lld [%d] %s ", (long long)time(NULL), level,
	//         component ? component : "unnamed");
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fwrite("\n", 1, 1, stderr);
	fflush(stderr);
}
lsb_logger lsb_vm_logger = { .context = (char*)"DECODE", .cb = logger };

static const char *short_options = "-hc:";
static const char *help =
"Usage: decode-exec [-c config] script.lua\n";

int main(int argc, char **argv) {
	lsb_lua_sandbox *lsb = NULL;
	char conffile[512] = CONF;
	char codefile[512];
	char *conf = NULL;
	char *p;
	int opt;

#if DEBUG==1
	set_debug(3);
#endif

	notice( "DECODE restricted execution environment v%s",VERSION);
	act("Copyright (C) 2017 Dyne.org foundation");
	do {
		opt = getopt(argc, argv, short_options);
		switch(opt) {
		case 'h':
			fprintf(stdout,"%s",help);
			exit(0);
			break;
		case 'c':
			snprintf(conffile,511,"%s",optarg);
			break;
		}
	} while(opt != -1);
	if(optarg)
		snprintf(codefile,511,"%s",optarg);
	else {
		error("usage: decode-exec script.lua");
		exit(1);
	}

	act("code: %s", codefile);

	conf = lsb_read_file(conffile);
	if(!conf) error("Error loading configuration: %s",conffile);
	else act("conf: %s", conffile);
	func("\n%s",conf);

	lsb = lsb_create(NULL, argv[1], conf, &lsb_vm_logger);
	if(!lsb) {
		error("Error creating sandbox: %s", lsb_get_error(lsb));
		goto teardown; }

	// load our own extensions
	{
		const luaL_Reg *lib = &luanachalib;
		notice("Loading crypto extensions");
		for (; lib->func; lib++) {
			func("%s",lib->name);
			lsb_add_function(lsb, lib->func, lib->name);
		}
	}


	{
		const char *r = lsb_init(lsb, NULL);
		if(r) {
			error(r);
			error(lsb_get_error(lsb));
			error("Error initialising sandbox. Execution aborted.");
			goto teardown; }
	}

	// while(lsb_get_state(lsb) == LSB_RUNNING)
	// 	act("running...");

	// // u = lsb_usage(lsb, LSB_UT_MEMORY, LSB_US_CURRENT);
	// // func("cur_mem %u", u);
	// // u = lsb_usage(lsb, LSB_UT_MEMORY, LSB_US_MAXIMUM);
	// // func("max_mem %u", u);
	// // u = lsb_usage(lsb, LSB_UT_MEMORY, LSB_US_LIMIT);
	// // func("mem_limit %u", u);
	// // u = lsb_usage(lsb, LSB_UT_INSTRUCTION, LSB_US_CURRENT);
	// // func("op: %u", u);

teardown:
	act("DECODE exec terminating.");
	if(conf) free(conf);
	if(lsb) {
		lsb_pcall_teardown(lsb);
		lsb_stop_sandbox_clean(lsb);
		p = lsb_destroy(lsb);
		if(p) free(p);
	}
	exit(0);
}
