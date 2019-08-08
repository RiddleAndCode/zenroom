#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
  #include "lua.hpp"
#else
  #include "lua.h"
  #include "lualib.h"
  #include "lauxlib.h"
#endif

#include <zen_error.h>
#include <zen_octet.h>
#include <zenroom_ring.h>
#include <lua_functions.h>

#ifdef __cplusplus
extern "C"{
#endif

#define KEYPROT(key) \
    lerror(L, "ECDSA engine has already a %s set:",key); \
    lerror(L, "Zenroom won't overwrite. Use a .new() instance.");

typedef struct {
    octet *pubkey;
    octet *seckey;
} ring_ecdsa;

ring_ecdsa* ring_ecdsa_init(lua_State *L) {
    ring_ecdsa *e = NULL;
    e = (ring_ecdsa*)lua_newuserdata(L, sizeof(ring_ecdsa));
    e->pubkey = NULL;
    e->seckey = NULL;
    return e;
}

 ring_ecdsa* ring_ecdsa_new(lua_State *L) {
    HERE();
    ring_ecdsa *e = ring_ecdsa_init(L);
    if(!e) { SAFE(e); return NULL; }

    luaL_getmetatable(L, "zenroom.ring");
    lua_setmetatable(L, -2);
    return(e);
}


ring_ecdsa* ring_ecdsa_arg(lua_State *L,int n) {
    void *ud = luaL_checkudata(L, n, "zenroom.ring");
    luaL_argcheck(L, ud != NULL, n, "ring ecdsa class expected");
    ring_ecdsa *e = (ring_ecdsa*)ud;
    return(e);
}

static int lua_ring_ecdsa_new(lua_State *L) {
    ring_ecdsa *e = ring_ecdsa_new(L);
    SAFE(e);
    return 1;
}

static int lua_ring_ecdsa_keygen(lua_State *L) {
    HERE();
    ring_ecdsa *e = ring_ecdsa_arg(L, 1); SAFE(e);
    if(e->seckey) {
        KEYPROT("private key"); }
    if(e->pubkey) {
        KEYPROT("public key"); }

    lua_createtable(L, 0, 2);
    octet *pk = o_new(L, RING_ECDSA_PUBLIC_LEN +0x0f); SAFE(pk);
    lua_setfield(L, -2, "public");
    octet *sk = o_new(L, RING_ECDSA_PRIVATE_LEN +0x0f); SAFE(sk);
    lua_setfield(L, -2, "private");

    pk->len = RING_ECDSA_PUBLIC_LEN;
    sk->len = RING_ECDSA_PRIVATE_LEN;
    rust_ring_ecdsa_generate_private(sk->val);
    rust_ring_ecdsa_public_from_private(sk->val, pk->val);

    e->pubkey = pk;
    e->seckey = sk;
    return 1;
}

static int lua_ring_ecdsa_public(lua_State *L) {
	HERE();
	/* int res; */
	ring_ecdsa *e = ring_ecdsa_arg(L, 1); SAFE(e);
	if(lua_isnoneornil(L, 2)) {
		if(!e->pubkey) {
			lua_pushnil(L);
			return 1; }
		o_dup(L,e->pubkey);
		return 1;
	}
    // set key
	if(e->pubkey!=NULL) {
		KEYPROT("public key"); }
	e->pubkey = o_arg(L, 2); SAFE(e->pubkey);
    /* TODO */
	/* res = (*e->ECP__PUBLIC_KEY_VALIDATE)(e->pubkey); */
	/* if(res<0) { */
	/* 	return lerror(L, "Public key argument is invalid."); } */
    return 0;
}

static int lua_ring_ecdsa_private(lua_State *L) {
	HERE();
	ring_ecdsa *e = ring_ecdsa_arg(L, 1); SAFE(e);
	if(lua_isnoneornil(L, 2)) {
		// no argument: return stored key
		if(!e->seckey) {
			lua_pushnil(L);
			return 1; }
		// export public key to octet
		o_dup(L, e->seckey);
		return 1;
	}
    // set key
	if(e->seckey!=NULL) {
		KEYPROT("private key"); }
	e->seckey = o_arg(L, 2); SAFE(e->seckey);
	octet *pk = o_new(L, RING_ECDSA_PUBLIC_LEN +0x0f); SAFE(pk);
    pk->len = RING_ECDSA_PUBLIC_LEN;
    rust_ring_ecdsa_public_from_private(e->seckey->val, pk->val);
    e->pubkey = pk;
    return 1;
}

static int lua_ring_ecdsa_sign(lua_State *L) {
	HERE();
	ring_ecdsa *e = ring_ecdsa_arg(L,1); SAFE(e);
	octet *m = o_arg(L,2); SAFE(m);
    octet *s = o_new(L, RING_ECDSA_SIGNATURE_LEN +0x0f); SAFE(s);
    s->len = RING_ECDSA_SIGNATURE_LEN;
    rust_ring_ecdsa_sign(e->seckey->val, m->val, m->len, s->val);
	return 1;
}

static int lua_ring_ecdsa_verify(lua_State *L) {
	HERE();
	ring_ecdsa *e = ring_ecdsa_arg(L,1); SAFE(e);
	octet *m = o_arg(L,2); SAFE(m);
	octet *s = o_arg(L,3); SAFE(s);
    lua_pushboolean(L, rust_ring_ecdsa_verify(e->pubkey->val, m->val, m->len, s->val));
	return 1;
}

static const struct luaL_Reg ring_class [] = {
    {"new", lua_ring_ecdsa_new},
    {NULL, NULL}
};

static const struct luaL_Reg ring_methods [] = {
    {"keygen", lua_ring_ecdsa_keygen},
	{"public", lua_ring_ecdsa_public},
	{"private", lua_ring_ecdsa_private},
	{"sign", lua_ring_ecdsa_sign},
	{"verify", lua_ring_ecdsa_verify},
    {NULL, NULL}
};

int luaopen_ring (lua_State *L) {
    zen_add_class(L, "ring", ring_class, ring_methods);
    return 1;
}

#ifdef __cplusplus
}
#endif
