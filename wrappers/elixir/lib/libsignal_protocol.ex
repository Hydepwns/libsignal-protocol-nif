defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol library.
  Provides a clean, idiomatic interface for secure messaging.
  """

  @on_load :load_nif

  def load_nif do
    # Try multiple possible paths for the NIF
    priv_dir = :code.priv_dir(:libsignal_protocol)
    nif_name = 'libsignal_protocol_nif'

    case priv_dir do
      {:error, :bad_name} ->
        # Fallback to relative path if priv_dir fails
        :erlang.load_nif('./priv/libsignal_protocol_nif', 0)
      priv_path ->
        nif_path = :filename.join(priv_path, nif_name)
        :erlang.load_nif(nif_path, 0)
    end
  end

  @doc """
  Initializes the Signal Protocol library.
  Returns `:ok` on success or `{:error, reason}` on failure.
  """
  @spec init() :: :ok | {:error, String.t()}
  def init do
    try do
      case :libsignal_protocol_nif.init() do
        :ok -> :ok
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF not loaded - libsignal_protocol_nif.init/0 not found"}
    catch
      :error, :undef ->
        {:error, "NIF not loaded - function undefined"}
    end
  end

  @doc """
  Creates a new session for a recipient using a public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(public_key) when is_binary(public_key) do
    try do
      case :libsignal_protocol_nif.create_session(public_key) do
        {:ok, session} -> {:ok, session}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function create_session/1 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function create_session/1 undefined"}
    end
  end

  @doc """
  Creates a new session using local private key and remote public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(local_private_key, remote_public_key)
      when is_binary(local_private_key) and is_binary(remote_public_key) do
    try do
      case :libsignal_protocol_nif.create_session(local_private_key, remote_public_key) do
        {:ok, session} -> {:ok, session}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function create_session/2 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function create_session/2 undefined"}
    end
  end

  @doc """
  Generates a new identity key pair.
  Returns `{:ok, {public_key, signature}}` on success.
  """
  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, String.t()}
  def generate_identity_key_pair do
    try do
      case :libsignal_protocol_nif.generate_identity_key_pair() do
        {:ok, {public_key, signature}} -> {:ok, {public_key, signature}}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function generate_identity_key_pair/0 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function generate_identity_key_pair/0 undefined"}
    end
  end

  # Simplified API - only include the functions that are most likely to work
  # Other functions can be added once basic functionality is confirmed

  # NIF stubs - these will be replaced by the actual NIF functions
  def load_nif_stub, do: :erlang.nif_error(:nif_not_loaded)
end
