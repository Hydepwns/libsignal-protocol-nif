-module(libsignal_protocol_gleam_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    libsignal_protocol_gleam_sup:start_link().

stop(_State) ->
    ok.
