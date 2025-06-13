defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol library.
  Provides a clean, idiomatic interface for secure messaging.
  """

  @doc """
  Initializes the Signal Protocol library.
  Returns `:ok` on success or `{:error, reason}` on failure.
  """
  @spec init() :: :ok | {:error, String.t()}
  def init do
    case :libsignal_protocol_nif.init() do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Creates a new session for a recipient.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def create_session(recipient_id) when is_binary(recipient_id) do
    :libsignal_protocol_nif.create_session(recipient_id)
  end

  @doc """
  Encrypts a message using the given session.
  Returns `{:ok, encrypted_message}` on success or `{:error, reason}` on failure.
  """
  @spec encrypt_message(String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def encrypt_message(session, message) when is_binary(session) and is_binary(message) do
    :libsignal_protocol_nif.encrypt_message(session, message)
  end

  @doc """
  Decrypts a message using the given session.
  Returns `{:ok, decrypted_message}` on success or `{:error, reason}` on failure.
  """
  @spec decrypt_message(String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def decrypt_message(session, encrypted_message) when is_binary(session) and is_binary(encrypted_message) do
    :libsignal_protocol_nif.decrypt_message(session, encrypted_message)
  end
end 