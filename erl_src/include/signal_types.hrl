-record(session,
        {id,
         local_identity_key,
         remote_identity_key,
         pre_key_id,
         signed_pre_key_id,
         ephemeral_key,
         chain_key,
         message_keys}).

-type identity_key_pair() :: {PublicKey :: binary(), PrivateKey :: binary()}.
-type pre_key() :: {KeyId :: integer(), PublicKey :: binary()}.
-type signed_pre_key() ::
    {KeyId :: integer(), PublicKey :: binary(), Signature :: binary()}.
-type pre_key_bundle() ::
    {RegistrationId :: integer(),
     DeviceId :: integer(),
     PreKey :: pre_key(),
     SignedPreKey :: signed_pre_key(),
     IdentityKey :: binary()}.
-type session() ::
    #{id => binary(),
      local_identity_key => binary(),
      remote_identity_key => binary(),
      pre_key_id => integer() | undefined,
      signed_pre_key_id => integer() | undefined,
      ephemeral_key => binary() | undefined,
      chain_key => binary() | undefined,
      message_keys => map()}.
-type message() :: binary().
-type ciphertext() :: binary().
