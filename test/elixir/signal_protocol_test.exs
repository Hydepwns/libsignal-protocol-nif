defmodule SignalProtocolTest do
  use ExUnit.Case
  alias SignalProtocol

  setup do
    {:ok, _} = SignalProtocol.start()
    :ok
  end

  describe "identity key generation" do
    test "generates valid identity key pair" do
      assert {:ok, {public_key, signature}} = SignalProtocol.generate_identity_key_pair()
      assert is_binary(public_key)
      assert is_binary(signature)
      assert byte_size(public_key) == 32
      assert byte_size(signature) == 64
    end
  end

  describe "pre-key generation" do
    test "generates valid pre-key" do
      key_id = :rand.uniform(1000)
      assert {:ok, {^key_id, public_key}} = SignalProtocol.generate_pre_key(key_id)
      assert is_binary(public_key)
      assert byte_size(public_key) == 32
    end
  end

  describe "signed pre-key generation" do
    test "generates valid signed pre-key" do
      {:ok, {identity_key, _}} = SignalProtocol.generate_identity_key_pair()
      key_id = :rand.uniform(1000)
      assert {:ok, {^key_id, public_key, signature}} = 
        SignalProtocol.generate_signed_pre_key(identity_key, key_id)
      assert is_binary(public_key)
      assert is_binary(signature)
      assert byte_size(public_key) == 32
      assert byte_size(signature) == 64
    end
  end

  describe "session management" do
    test "creates valid session" do
      {:ok, {local_identity_key, _}} = SignalProtocol.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = SignalProtocol.generate_identity_key_pair()
      assert {:ok, session_id} = SignalProtocol.create_session(local_identity_key, remote_identity_key)
      assert is_binary(session_id)
    end
  end

  describe "message encryption/decryption" do
    test "encrypts and decrypts message" do
      {:ok, {local_identity_key, _}} = SignalProtocol.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = SignalProtocol.generate_identity_key_pair()
      {:ok, session_id} = SignalProtocol.create_session(local_identity_key, remote_identity_key)
      
      message = "Hello, Signal Protocol!"
      assert {:ok, ciphertext} = SignalProtocol.encrypt_message(session_id, message)
      assert is_binary(ciphertext)
      
      assert {:ok, decrypted} = SignalProtocol.decrypt_message(session_id, ciphertext)
      assert decrypted == message
    end
  end

  describe "crypto operations" do
    test "signs and verifies data" do
      {:ok, {public_key, private_key}} = SignalProtocol.generate_identity_key_pair()
      data = "Hello, World!"
      
      assert {:ok, signature} = SignalProtocol.sign_data(private_key, data)
      assert is_binary(signature)
      
      assert {:ok, true} = SignalProtocol.verify_signature(public_key, data, signature)
    end

    test "encrypts and decrypts with key and IV" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      data = "Hello, World!"
      
      assert {:ok, ciphertext} = SignalProtocol.encrypt_message(key, iv, data)
      assert is_binary(ciphertext)
      
      assert {:ok, decrypted} = SignalProtocol.decrypt_message(key, iv, ciphertext)
      assert decrypted == data
    end

    test "generates HMAC" do
      key = :crypto.strong_rand_bytes(32)
      data = "Hello, World!"
      
      assert {:ok, mac} = SignalProtocol.hmac_sha256(key, data)
      assert is_binary(mac)
      assert byte_size(mac) == 32
    end

    test "generates SHA-256 hash" do
      data = "Hello, World!"
      
      assert {:ok, hash} = SignalProtocol.sha256(data)
      assert is_binary(hash)
      assert byte_size(hash) == 32
    end

    test "generates random bytes" do
      n = 32
      assert {:ok, bytes} = SignalProtocol.random_bytes(n)
      assert is_binary(bytes)
      assert byte_size(bytes) == n
    end
  end
end 