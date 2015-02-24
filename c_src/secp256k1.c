#include <string.h>
#include "erl_nif.h"
#include "secp256k1.h"


static ERL_NIF_TERM secp256k1_ecdsa_sign_nif(ErlNifEnv* env, int argc,
                                             const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM secp256k1_ecdsa_verify_nif(ErlNifEnv* env, int argc,
                                               const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM secp256k1_ec_pubkey_create_nif(ErlNifEnv* env, int argc,
                                                   const ERL_NIF_TERM argv[]);


static ErlNifFunc nif_funcs[] =
{
    {"secp256k1_ecdsa_sign", 4, secp256k1_ecdsa_sign_nif},
    {"secp256k1_ecdsa_verify", 3, secp256k1_ecdsa_verify_nif},
    {"secp256k1_ec_pubkey_create", 2, secp256k1_ec_pubkey_create_nif}
};

static ERL_NIF_TERM secp256k1_ecdsa_sign_nif(ErlNifEnv* env, int argc,
                                   const ERL_NIF_TERM argv[])
{
  // Arguments
  // msg32:  the 32-byte message hash being signed (cannot be NULL)
  if (!enif_is_binary(env, argv[0])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary msg32;
  if (!enif_inspect_binary(env, argv[0], &msg32)) {
    return enif_make_badarg(env);
  }
  if (msg32.size != 32) {
    return enif_make_badarg(env);
  }
  // seckey: pointer to a 32-byte secret key (cannot be NULL)
  if (!enif_is_binary(env, argv[1])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary seckey;
  if (!enif_inspect_binary(env, argv[1], &seckey)) {
    return enif_make_badarg(env);
  }
  if (seckey.size != 32) {
    return enif_make_badarg(env);
  }
  // noncefp:pointer to a nonce generation function.
  if (!enif_is_atom(env, argv[2])) {
    return enif_make_badarg(env);
  }
  ERL_NIF_TERM rfc6979_nonce = enif_make_atom(env, "rfc6979");
  ERL_NIF_TERM default_nonce = enif_make_atom(env, "default");
  if (!(enif_is_identical(rfc6979_nonce, argv[2]) || enif_is_identical(default_nonce, argv[2]))) {
    return enif_make_badarg(env);
  }
  secp256k1_nonce_function_t nonce;
  if (enif_is_identical(rfc6979_nonce, argv[2])) {
    nonce = secp256k1_nonce_function_rfc6979;
  }
  if (enif_is_identical(default_nonce, argv[2])) {
    nonce = secp256k1_nonce_function_default;
  }
  // ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
  if (!enif_is_binary(env, argv[3])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary ndata;
  if (!enif_inspect_binary(env, argv[3], &ndata)) {
    return enif_make_badarg(env);
  }
  void *ndata_;
  if (ndata.size == 0) {
    ndata_ = NULL;
  } else {
    ndata_ = (void *)ndata.data;
  }

  int siglen = 72;
  unsigned char *sig = malloc(siglen);

  int result = secp256k1_ecdsa_sign((const unsigned char *)msg32.data,
                                    sig, &siglen,
                                    (const unsigned char *)seckey.data,
                                    nonce, ndata_);

  if (result == 1) {
    ErlNifBinary bin;
    enif_alloc_binary(siglen, &bin);
    memcpy(bin.data, sig, siglen);
    free(sig);
    return enif_make_binary(env, &bin);
  } else {
    free(sig);
    return enif_make_atom(env, "error");
  }

}

static ERL_NIF_TERM secp256k1_ecdsa_verify_nif(ErlNifEnv* env, int argc,
                                   const ERL_NIF_TERM argv[])
{
  // Arguments
  // msg32:  the 32-byte message hash being signed (cannot be NULL)
  if (!enif_is_binary(env, argv[0])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary msg32;
  if (!enif_inspect_binary(env, argv[0], &msg32)) {
    return enif_make_badarg(env);
  }
  if (msg32.size != 32) {
    return enif_make_badarg(env);
  }
  // sig: the signature being verified (cannot be NULL)
  if (!enif_is_binary(env, argv[1])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary sig;
  if (!enif_inspect_binary(env, argv[1], &sig)) {
    return enif_make_badarg(env);
  }
  // pubkey:    the public key to verify with (cannot be NULL)
  if (!enif_is_binary(env, argv[2])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary pubkey;
  if (!enif_inspect_binary(env, argv[2], &pubkey)) {
    return enif_make_badarg(env);
  }

  int result = secp256k1_ecdsa_verify((const unsigned char *)msg32.data,
                                      (const unsigned char *)sig.data, sig.size,
                                      (const unsigned char *)pubkey.data, pubkey.size);

  switch(result) {
    case 1:
      return enif_make_atom(env, "correct");
    case 0:
      return enif_make_atom(env, "incorrect");
    case -1:
      return enif_make_atom(env, "invalid_public_key");
    case -2:
      return enif_make_atom(env, "invalid_signature");
    default:
      return enif_make_atom(env, "error");
  }
}

static ERL_NIF_TERM secp256k1_ec_pubkey_create_nif(ErlNifEnv* env, int argc,
                                                   const ERL_NIF_TERM argv[]) {
  // Arguments
  // seckey: pointer to a 32-byte secret key (cannot be NULL)
  if (!enif_is_binary(env, argv[0])) {
    return enif_make_badarg(env);
  }
  ErlNifBinary seckey;
  if (!enif_inspect_binary(env, argv[0], &seckey)) {
    return enif_make_badarg(env);
  }
  if (seckey.size != 32) {
    return enif_make_badarg(env);
  }
  // compressed: whether the computed public key should be compressed
  if (!enif_is_atom(env, argv[1])) {
    return enif_make_badarg(env);
  }
  ERL_NIF_TERM true_atom = enif_make_atom(env, "true");
  ERL_NIF_TERM false_atom = enif_make_atom(env, "false");
  if (!(enif_is_identical(true_atom, argv[1]) || enif_is_identical(false_atom, argv[1]))) {
    return enif_make_badarg(env);
  }
  int compressed = 0;
  if (enif_is_identical(true_atom, argv[1])) {
    compressed = 1;
  }

  unsigned char *pubkey = malloc(compressed ? 33 : 65);
  int pubkeylen;

  int result = secp256k1_ec_pubkey_create(pubkey, &pubkeylen, (const unsigned char *)seckey.data, compressed);

  if (result == 1) {
    ErlNifBinary bin;
    enif_alloc_binary(pubkeylen, &bin);
    memcpy(bin.data, pubkey, pubkeylen);
    free(pubkey);
    return enif_make_binary(env, &bin);
  } else {
    free(pubkey);
    return enif_make_atom(env, "error");
  }


}


static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN);

    return 0;
}

static void on_unload(ErlNifEnv* env, void* priv_data) {
  secp256k1_stop();
}

ERL_NIF_INIT(secp256k1, nif_funcs, &on_load, NULL, NULL, &on_unload);
