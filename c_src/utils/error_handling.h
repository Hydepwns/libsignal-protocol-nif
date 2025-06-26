#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#include <erl_nif.h>

// Enhanced error handling function
ERL_NIF_TERM make_openssl_error(ErlNifEnv *env);

#endif // ERROR_HANDLING_H