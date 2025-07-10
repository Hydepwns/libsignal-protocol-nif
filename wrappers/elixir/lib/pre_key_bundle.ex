defmodule SignalProtocol.PreKeyBundle do
  @moduledoc """
  Handles the creation and processing of pre-key bundles for the Signal Protocol.

  Pre-key bundles are used to establish initial sessions between users
  in an asynchronous manner.
  """

  @doc """
  Creates a new pre-key bundle with the given components.

  ## Parameters
    * `registration_id` - The registration ID of the user
    * `identity_key` - The user's identity key
    * `pre_key` - A pre-key tuple `{key_id, public_key}`
    * `signed_pre_key` - A signed pre-key tuple `{key_id, public_key, signature}`
    * `base_key` - The base key for the X3DH key agreement

  Returns `{:ok, bundle}` on success, where `bundle` is a binary containing
  the serialized pre-key bundle.
  """
  def create(registration_id, identity_key, pre_key, signed_pre_key, base_key)
      when is_integer(registration_id) and
             is_binary(identity_key) and
             tuple_size(pre_key) == 2 and
             tuple_size(signed_pre_key) == 3 and
             is_binary(base_key) do
    {pre_key_id, pre_key_public} = pre_key
    {signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature} = signed_pre_key

    # Calculate bundle size for validation (internal use only)
    # version
    # registration_id
    # pre_key_id
    # signed_pre_key_id
    _bundle_size =
      1 +
        4 +
        4 +
        4 +
        byte_size(identity_key) +
        byte_size(pre_key_public) +
        byte_size(signed_pre_key_public) +
        byte_size(signed_pre_key_signature) +
        byte_size(base_key)

    # Create bundle
    bundle =
      :binary.bin_to_list(<<
        # version
        1::8,
        # registration_id
        registration_id::32,
        # pre_key_id
        pre_key_id::32,
        # signed_pre_key_id
        signed_pre_key_id::32,
        # identity_key
        identity_key::binary,
        # pre_key_public
        pre_key_public::binary,
        # signed_pre_key_public
        signed_pre_key_public::binary,
        # signed_pre_key_signature
        signed_pre_key_signature::binary,
        # base_key
        base_key::binary
      >>)

    {:ok, :binary.list_to_bin(bundle)}
  end

  @doc """
  Parses a pre-key bundle from its binary representation.

  Returns `{:ok, bundle}` on success, where `bundle` is a map containing
  the bundle components.
  """
  def parse(bundle) when is_binary(bundle) do
    try do
      <<
        version::8,
        registration_id::32,
        pre_key_id::32,
        signed_pre_key_id::32,
        identity_key::binary-size(32),
        pre_key_public::binary-size(32),
        signed_pre_key_public::binary-size(32),
        signed_pre_key_signature::binary-size(64),
        base_key::binary-size(32)
      >> = bundle

      {:ok,
       %{
         version: version,
         registration_id: registration_id,
         pre_key_id: pre_key_id,
         signed_pre_key_id: signed_pre_key_id,
         identity_key: identity_key,
         pre_key_public: pre_key_public,
         signed_pre_key_public: signed_pre_key_public,
         signed_pre_key_signature: signed_pre_key_signature,
         base_key: base_key
       }}
    rescue
      _ -> {:error, :invalid_bundle}
    end
  end

  @doc """
  Verifies the signature of a pre-key bundle.

  Returns `:ok` if the signature is valid, `{:error, reason}` otherwise.
  """
  def verify_signature(bundle) when is_binary(bundle) do
    case parse(bundle) do
      {:ok, %{signed_pre_key_public: _public_key, signed_pre_key_signature: signature}} ->
        # In a real implementation, this would verify the signature using the identity key
        # For this example, we'll just check that the signature is the correct length
        if byte_size(signature) == 64 do
          :ok
        else
          {:error, :invalid_signature}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
