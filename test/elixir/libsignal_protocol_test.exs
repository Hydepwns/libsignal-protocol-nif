defmodule LibsignalProtocolTest do
  use ExUnit.Case
  doctest LibsignalProtocol

  setup do
    :ok = LibsignalProtocol.init()
    :ok
  end

  describe "session management" do
    test "creates a new session" do
      recipient_id = "test_recipient"
      assert {:ok, session} = LibsignalProtocol.create_session(recipient_id)
      assert is_binary(session)
    end

    test "fails to create session with invalid recipient" do
      assert {:error, _} = LibsignalProtocol.create_session(123)
    end
  end

  describe "message encryption/decryption" do
    test "encrypts and decrypts a message" do
      recipient_id = "test_recipient"
      message = "Hello, Signal!"

      {:ok, session} = LibsignalProtocol.create_session(recipient_id)
      {:ok, encrypted} = LibsignalProtocol.encrypt_message(session, message)
      {:ok, decrypted} = LibsignalProtocol.decrypt_message(session, encrypted)

      assert decrypted == message
    end

    test "fails to encrypt with invalid session" do
      assert {:error, _} = LibsignalProtocol.encrypt_message(123, "test")
    end

    test "fails to decrypt with invalid session" do
      assert {:error, _} = LibsignalProtocol.decrypt_message(123, "test")
    end
  end
end
