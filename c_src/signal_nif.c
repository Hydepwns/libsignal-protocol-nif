#include <erl_nif.h>
#include <string.h>

static ERL_NIF_TERM test_function(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM test_crypto(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM sha256(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    // For now, just return a dummy hash
    unsigned char dummy_hash[32] = {0};
    ERL_NIF_TERM hash_term;
    unsigned char *bin_data = enif_make_new_binary(env, 32, &hash_term);
    memcpy(bin_data, dummy_hash, 32);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), hash_term);
}

static ERL_NIF_TERM generate_curve25519_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // For now, just return dummy keys
    unsigned char dummy_private[32] = {0};
    unsigned char dummy_public[32] = {0};
    
    ERL_NIF_TERM private_term, public_term;
    unsigned char *private_data = enif_make_new_binary(env, 32, &private_term);
    unsigned char *public_data = enif_make_new_binary(env, 32, &public_term);
    
    memcpy(private_data, dummy_private, 32);
    memcpy(public_data, dummy_public, 32);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, private_term, public_term));
}

// Define the NIF function array with the correct 4-field structure for Erlang 27
static ErlNifFunc nif_funcs[] = {
    {"test_function", 0, test_function, 0},
    {"test_crypto", 0, test_crypto, 0},
    {"sha256", 1, sha256, 0},
    {"generate_curve25519_keypair", 0, generate_curve25519_keypair, 0}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(signal_nif, nif_funcs, on_load, NULL, NULL, on_unload)

 