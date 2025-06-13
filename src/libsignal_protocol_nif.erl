-module(libsignal_protocol_nif).

-on_load(init/0).

-export([dummy/0]).

init() ->
    erlang:load_nif("priv/libsignal_protocol_nif", 0).

dummy() ->
    "NIF not loaded". 