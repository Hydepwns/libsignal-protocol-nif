#include "error_handling.h"
#include <openssl/err.h>
#include "utils.h"

ERL_NIF_TERM make_openssl_error(ErlNifEnv *env)
{
  unsigned long err = ERR_get_error();
  char err_buf[256];

  if (err == 0)
  {
    return make_error(env, "unknown OpenSSL error");
  }

  ERR_error_string_n(err, err_buf, sizeof(err_buf));
  return make_error(env, err_buf);
}