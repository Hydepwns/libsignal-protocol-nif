defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol library.
  Provides a clean, idiomatic interface for secure messaging.
  """

  @on_load :load_nif

  def load_nif do
    nif_path = :filename.join(:code.priv_dir(:libsignal_protocol), 'libsignal_protocol_nif')
    :erlang.load_nif(nif_path, 0)
  end

  @doc """
  Initializes the Signal Protocol library.
  Returns `:ok` on success or `{:error, reason}` on failure.
  """
  @spec init() :: :ok | {:error, String.t()}
  def init do
    case :libsignal_protocol_nif.init() do
      :ok -> :ok
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Creates a new session for a recipient using a public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(public_key) when is_binary(public_key) do
    case :libsignal_protocol_nif.create_session(public_key) do
      {:ok, session} -> {:ok, session}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Creates a new session using local private key and remote public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(local_private_key, remote_public_key)
      when is_binary(local_private_key) and is_binary(remote_public_key) do
    case :libsignal_protocol_nif.create_session(local_private_key, remote_public_key) do
      {:ok, session} -> {:ok, session}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Encrypts a message using the given session.
  Returns `{:ok, encrypted_message}` on success or `{:error, reason}` on failure.
  """
  @spec encrypt_message(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def encrypt_message(session, message) when is_binary(session) and is_binary(message) do
    case :libsignal_protocol_nif.encrypt_message(session, message) do
      {:ok, ciphertext} -> {:ok, ciphertext}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Decrypts a message using the given session.
  Returns `{:ok, decrypted_message}` on success or `{:error, reason}` on failure.
  """
  @spec decrypt_message(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def decrypt_message(session, encrypted_message)
      when is_binary(session) and is_binary(encrypted_message) do
    case :libsignal_protocol_nif.decrypt_message(session, encrypted_message) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Generates a new identity key pair.
  Returns `{:ok, {public_key, signature}}` on success.
  """
  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, String.t()}
  def generate_identity_key_pair do
    case :libsignal_protocol_nif.generate_identity_key_pair() do
      {:ok, {public_key, signature}} -> {:ok, {public_key, signature}}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Generates a new pre-key with the given ID.
  Returns `{:ok, {key_id, public_key}}` on success.
  """
  @spec generate_pre_key(integer()) :: {:ok, {integer(), binary()}} | {:error, String.t()}
  def generate_pre_key(key_id) when is_integer(key_id) do
    case :libsignal_protocol_nif.generate_pre_key(key_id) do
      {:ok, {key_id, public_key}} -> {:ok, {key_id, public_key}}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Generates a new signed pre-key with the given ID, signed by the identity key.
  Returns `{:ok, {key_id, public_key, signature}}` on success.
  """
  @spec generate_signed_pre_key(binary(), integer()) :: {:ok, {integer(), binary(), binary()}} | {:error, String.t()}
  def generate_signed_pre_key(identity_key, key_id)
      when is_binary(identity_key) and is_integer(key_id) do
    case :libsignal_protocol_nif.generate_signed_pre_key(identity_key, key_id) do
      {:ok, {key_id, public_key, signature}} -> {:ok, {key_id, public_key, signature}}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  @doc """
  Processes a pre-key bundle to establish a session.
  Returns `:ok` on success.
  """
  @spec process_pre_key_bundle(binary(), binary()) :: :ok | {:error, String.t()}
  def process_pre_key_bundle(session, bundle)
      when is_binary(session) and is_binary(bundle) do
    case :libsignal_protocol_nif.process_pre_key_bundle(session, bundle) do
      :ok -> :ok
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  # NIF stubs - these will be replaced by the actual NIF functions
  def load_nif_stub, do: :erlang.nif_error(:nif_not_loaded)
end
