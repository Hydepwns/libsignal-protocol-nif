-module(signal_protocol).

-export([
    start/0,
    stop/0,
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    create_session/2,
    process_pre_key_bundle/2,
    encrypt_message/2,
    decrypt_message/2
]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
    sessions = #{} :: map()
}).

%% Public API

start() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:stop(?MODULE).

generate_identity_key_pair() ->
    gen_server:call(?MODULE, generate_identity_key_pair).

generate_pre_key(KeyId) ->
    gen_server:call(?MODULE, {generate_pre_key, KeyId}).

generate_signed_pre_key(IdentityKey, KeyId) ->
    gen_server:call(?MODULE, {generate_signed_pre_key, IdentityKey, KeyId}).

create_session(LocalIdentityKey, RemoteIdentityKey) ->
    gen_server:call(?MODULE, {create_session, LocalIdentityKey, RemoteIdentityKey}).

process_pre_key_bundle(Session, Bundle) ->
    gen_server:call(?MODULE, {process_pre_key_bundle, Session, Bundle}).

encrypt_message(Session, Message) ->
    gen_server:call(?MODULE, {encrypt_message, Session, Message}).

decrypt_message(Session, Ciphertext) ->
    gen_server:call(?MODULE, {decrypt_message, Session, Ciphertext}).

%% gen_server callbacks

init([]) ->
    {ok, #state{}}.

handle_call(generate_identity_key_pair, _From, State) ->
    Result = signal_nif:generate_identity_key_pair(),
    {reply, Result, State};

handle_call({generate_pre_key, KeyId}, _From, State) ->
    Result = signal_nif:generate_pre_key(KeyId),
    {reply, Result, State};

handle_call({generate_signed_pre_key, IdentityKey, KeyId}, _From, State) ->
    Result = signal_nif:generate_signed_pre_key(IdentityKey, KeyId),
    {reply, Result, State};

handle_call({create_session, LocalIdentityKey, RemoteIdentityKey}, _From, State) ->
    Result = signal_nif:create_session(LocalIdentityKey, RemoteIdentityKey),
    {reply, Result, State};

handle_call({process_pre_key_bundle, Session, Bundle}, _From, State) ->
    Result = signal_nif:process_pre_key_bundle(Session, Bundle),
    {reply, Result, State};

handle_call({encrypt_message, Session, Message}, _From, State) ->
    Result = signal_nif:encrypt_message(Session, Message),
    {reply, Result, State};

handle_call({decrypt_message, Session, Ciphertext}, _From, State) ->
    Result = signal_nif:decrypt_message(Session, Ciphertext),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}. 