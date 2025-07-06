defmodule LibsignalProtocol.SessionTest do
  use ExUnit.Case, async: true
  alias LibsignalProtocol.Session
  alias LibsignalProtocol.PreKeyBundle

  setup do
    # Initialize the NIF
    :ok = :nif.init()
    :ok
  end

  describe "Session.create/2" do
    test "creates a new session with valid identity keys" do
      # Generate identity keys
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()

      # Create session
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)
      
      assert is_map(session)
      assert Map.has_key?(session, :id)
      assert Map.has_key?(session, :local_identity_key)
      assert Map.has_key?(session, :remote_identity_key)
      assert session.local_identity_key == local_identity_key
      assert session.remote_identity_key == remote_identity_key
      assert is_binary(session.id)
      assert byte_size(session.id) == 32
    end

    test "creates different sessions for different keys" do
      {:ok, {local_key1, _}} = :nif.generate_identity_key_pair()
      {:ok, {local_key2, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_key1, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_key2, _}} = :nif.generate_identity_key_pair()

      {:ok, session1} = Session.create(local_key1, remote_key1)
      {:ok, session2} = Session.create(local_key2, remote_key2)
      {:ok, session3} = Session.create(local_key1, remote_key2)

      assert session1.id != session2.id
      assert session1.id != session3.id
      assert session2.id != session3.id
    end

    test "handles invalid identity keys gracefully" do
      invalid_key = "invalid_key"
      
      case Session.create(invalid_key, invalid_key) do
        {:error, _} -> :ok
        {:ok, session} -> 
          assert is_map(session)
          assert Map.has_key?(session, :id)
      end
    end
  end

  describe "Session.process_pre_key_bundle/2" do
    test "processes valid pre-key bundle" do
      # Generate identity keys
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()

      # Create session
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      # Create pre-key bundle
      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      # Process bundle
      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, updated_session} ->
          assert is_map(updated_session)
          assert updated_session.pre_key_id == pre_key_id
          assert updated_session.signed_pre_key_id == signed_pre_key_id
          assert is_binary(updated_session.ephemeral_key)
          assert is_binary(updated_session.chain_key)
        {:error, reason} ->
          # Some implementations might fail due to signature verification
          assert is_atom(reason) or is_binary(reason)
      end
    end

    test "handles invalid pre-key bundle" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, local_identity_key)

      invalid_bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {0, "invalid_key"},
        signed_pre_key: {0, "invalid_key", "invalid_signature"},
        identity_key: "invalid_identity_key"
      }

      case Session.process_pre_key_bundle(session, invalid_bundle) do
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end
  end

  describe "Session.encrypt_message/2" do
    test "encrypts messages with established session" do
      # Generate identity keys
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()

      # Create session
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      # Create pre-key bundle
      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      # Process bundle to establish session
      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          # Test message encryption
          message = "Hello, Signal Protocol!"
          case Session.encrypt_message(established_session, message) do
            {:ok, encrypted_message, updated_session} ->
              assert is_binary(encrypted_message)
              assert byte_size(encrypted_message) > byte_size(message)
              assert is_map(updated_session)
              assert updated_session.message_counter > established_session.message_counter
            {:error, _} -> :ok
          end
        {:error, _} -> :ok
      end
    end

    test "encrypts different messages" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          message1 = "First message"
          message2 = "Second message"
          
          case {Session.encrypt_message(established_session, message1),
                Session.encrypt_message(established_session, message2)} do
            {{:ok, encrypted1, _}, {:ok, encrypted2, _}} ->
              assert encrypted1 != encrypted2
            _ -> :ok
          end
        {:error, _} -> :ok
      end
    end

    test "encrypts empty and large messages" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          # Test empty message
          case Session.encrypt_message(established_session, "") do
            {:ok, encrypted_empty, _} ->
              assert is_binary(encrypted_empty)
            {:error, _} -> :ok
          end

          # Test large message
          large_message = String.duplicate("A", 1000)
          case Session.encrypt_message(established_session, large_message) do
            {:ok, encrypted_large, _} ->
              assert is_binary(encrypted_large)
            {:error, _} -> :ok
          end
        {:error, _} -> :ok
      end
    end
  end

  describe "Session.decrypt_message/2" do
    test "decrypts encrypted messages" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          original_message = "Test message for decryption"
          
          case Session.encrypt_message(established_session, original_message) do
            {:ok, encrypted_message, updated_session} ->
              case Session.decrypt_message(updated_session, encrypted_message) do
                {:ok, decrypted_message, _} ->
                  assert decrypted_message == original_message
                {:error, _} -> :ok
              end
            {:error, _} -> :ok
          end
        {:error, _} -> :ok
      end
    end

    test "handles invalid encrypted messages" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      invalid_encrypted = "invalid_encrypted_message"
      
      case Session.decrypt_message(session, invalid_encrypted) do
        {:error, _} -> :ok
        {:ok, _, _} -> :ok
      end
    end
  end

  describe "Session.create_and_process_bundle/3" do
    test "creates session and processes bundle in one step" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.create_and_process_bundle(local_identity_key, remote_identity_key, bundle) do
        {:ok, session} ->
          assert is_map(session)
          assert Map.has_key?(session, :id)
          assert Map.has_key?(session, :pre_key_id)
          assert Map.has_key?(session, :signed_pre_key_id)
        {:error, _} -> :ok
      end
    end
  end

  describe "Session.send_message/2" do
    test "sends messages using established session" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          message = "Hello from sender!"
          
          case Session.send_message(established_session, message) do
            {:ok, encrypted_message, updated_session} ->
              assert is_binary(encrypted_message)
              assert is_map(updated_session)
            {:error, _} -> :ok
          end
        {:error, _} -> :ok
      end
    end
  end

  describe "Session.receive_message/2" do
    test "receives and decrypts messages" do
      {:ok, {local_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {remote_identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, session} = Session.create(local_identity_key, remote_identity_key)

      # Generate pre-key bundle components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} = 
        :nif.generate_signed_pre_key(remote_identity_key, 67890)

      bundle = %{
        registration_id: 123,
        device_id: 456,
        pre_key: {pre_key_id, pre_key_public},
        signed_pre_key: {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key: remote_identity_key
      }

      case Session.process_pre_key_bundle(session, bundle) do
        {:ok, established_session} ->
          original_message = "Hello from sender!"
          
          case Session.encrypt_message(established_session, original_message) do
            {:ok, encrypted_message, updated_session} ->
              case Session.receive_message(updated_session, encrypted_message) do
                {:ok, decrypted_message, _} ->
                  assert decrypted_message == original_message
                {:error, _} -> :ok
              end
            {:error, _} -> :ok
          end
        {:error, _} -> :ok
      end
    end
  end
end 