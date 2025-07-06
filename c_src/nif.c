#include <erl_nif.h>

static ERL_NIF_TERM test_function(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
    {"test_function", 0, test_function},
    {NULL, 0, NULL}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

ERL_NIF_INIT(signal_nif, nif_funcs, on_load, NULL, NULL, on_unload) 