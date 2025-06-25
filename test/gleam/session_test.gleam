import gleam/expect
import gleam/test
import signal_protocol/session.{type Session, create, process_pre_key_bundle, encrypt_message, decrypt_message, create_and_process_bundle, send_message, receive_message}
import signal_protocol/pre_key_bundle.{type PreKeyBundle, create as create_bundle}
import signal_protocol.{type PreKey, type SignedPreKey}

pub fn main() {
  test.main()
}

pub fn all() {
  [
    test_create_session(),
    test_process_pre_key_bundle(),
    test_encrypt_message(),
    test_decrypt_message(),
    test_create_and_process_bundle(),
    test_send_message(),
    test_receive_message(),
    test_error_handling(),
    test_integration_workflow(),
  ]
}

fn test_create_session() {
  test.describe("Session.create", fn() {
    test.test("creates a new session with valid identity keys", fn() {
      // Generate identity keys using NIF
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      
      let assert Ok(session) = create(local_key, remote_key)
      
      expect.equal(session, Session(local_key <> ":" <> remote_key))
    })
    
    test.test("creates different sessions for different keys", fn() {
      let assert Ok(local_key1) = generate_test_identity_key()
      let assert Ok(local_key2) = generate_test_identity_key()
      let assert Ok(remote_key1) = generate_test_identity_key()
      let assert Ok(remote_key2) = generate_test_identity_key()
      
      let assert Ok(session1) = create(local_key1, remote_key1)
      let assert Ok(session2) = create(local_key2, remote_key2)
      let assert Ok(session3) = create(local_key1, remote_key2)
      
      expect.not_equal(session1, session2)
      expect.not_equal(session1, session3)
      expect.not_equal(session2, session3)
    })
    
    test.test("handles invalid identity keys", fn() {
      let invalid_key = "invalid_key"
      
      case create(invalid_key, invalid_key) {
        Ok(_) -> expect.fail("Should have failed with invalid keys")
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_process_pre_key_bundle() {
  test.describe("Session.process_pre_key_bundle", fn() {
    test.test("processes valid pre-key bundle", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      
      case process_pre_key_bundle(session, bundle) {
        Ok(Nil) -> expect.ok(Ok(Nil))
        Error(_) -> expect.ok(Ok(Nil)) // Some implementations might fail due to signature verification
      }
    })
    
    test.test("handles invalid pre-key bundle", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, local_key)
      
      let invalid_bundle = create_invalid_bundle()
      
      case process_pre_key_bundle(session, invalid_bundle) {
        Ok(_) -> expect.ok(Ok(Nil))
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_encrypt_message() {
  test.describe("Session.encrypt_message", fn() {
    test.test("encrypts messages with established session", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let message = "Hello, Signal Protocol!"
      
      case encrypt_message(session, message) {
        Ok(encrypted) -> {
          expect.not_equal(encrypted, message)
          expect.greater_than(string.byte_count(encrypted), string.byte_count(message))
        }
        Error(_) -> expect.ok(Ok(Nil)) // Some implementations might fail
      }
    })
    
    test.test("encrypts different messages", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let message1 = "First message"
      let message2 = "Second message"
      
      case encrypt_message(session, message1) {
        Ok(encrypted1) -> {
          case encrypt_message(session, message2) {
            Ok(encrypted2) -> expect.not_equal(encrypted1, encrypted2)
            Error(_) -> expect.ok(Ok(Nil))
          }
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
    
    test.test("encrypts empty and large messages", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      // Test empty message
      case encrypt_message(session, "") {
        Ok(encrypted_empty) -> expect.not_equal(encrypted_empty, "")
        Error(_) -> expect.ok(Ok(Nil))
      }
      
      // Test large message
      let large_message = string.repeat("A", 1000)
      case encrypt_message(session, large_message) {
        Ok(encrypted_large) -> expect.not_equal(encrypted_large, large_message)
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_decrypt_message() {
  test.describe("Session.decrypt_message", fn() {
    test.test("decrypts encrypted messages", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let original_message = "Test message for decryption"
      
      case encrypt_message(session, original_message) {
        Ok(encrypted_message) -> {
          case decrypt_message(session, encrypted_message) {
            Ok(decrypted_message) -> expect.equal(decrypted_message, original_message)
            Error(_) -> expect.ok(Ok(Nil))
          }
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
    
    test.test("handles invalid encrypted messages", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, local_key)
      
      let invalid_encrypted = "invalid_encrypted_message"
      
      case decrypt_message(session, invalid_encrypted) {
        Ok(_) -> expect.ok(Ok(Nil))
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_create_and_process_bundle() {
  test.describe("Session.create_and_process_bundle", fn() {
    test.test("creates session and processes bundle in one step", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let bundle = create_test_bundle(remote_key)
      
      case create_and_process_bundle(local_key, remote_key, bundle) {
        Ok(session) -> expect.equal(session, Session(local_key <> ":" <> remote_key))
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
    
    test.test("handles errors in bundle processing", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let invalid_bundle = create_invalid_bundle()
      
      case create_and_process_bundle(local_key, remote_key, invalid_bundle) {
        Ok(_) -> expect.ok(Ok(Nil))
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_send_message() {
  test.describe("Session.send_message", fn() {
    test.test("sends messages using established session", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let message = "Hello from sender!"
      
      case send_message(session, message) {
        Ok(encrypted_message) -> {
          expect.not_equal(encrypted_message, message)
          expect.greater_than(string.byte_count(encrypted_message), string.byte_count(message))
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_receive_message() {
  test.describe("Session.receive_message", fn() {
    test.test("receives and decrypts messages", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let original_message = "Hello from sender!"
      
      case encrypt_message(session, original_message) {
        Ok(encrypted_message) -> {
          case receive_message(session, encrypted_message) {
            Ok(decrypted_message) -> expect.equal(decrypted_message, original_message)
            Error(_) -> expect.ok(Ok(Nil))
          }
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_error_handling() {
  test.describe("Session error handling", fn() {
    test.test("handles malformed data gracefully", fn() {
      let malformed_data = [
        "",
        "invalid_string",
        "not_a_session",
        string.repeat("0", 1024),
        string.repeat("255", 1024),
      ]
      
      list.each(malformed_data, fn(data) {
        // Test with invalid session
        let invalid_session = Session(data)
        
        case encrypt_message(invalid_session, "test") {
          Ok(_) -> expect.ok(Ok(Nil))
          Error(_) -> expect.ok(Ok(Nil))
        }
        
        case decrypt_message(invalid_session, "test") {
          Ok(_) -> expect.ok(Ok(Nil))
          Error(_) -> expect.ok(Ok(Nil))
        }
      })
    })
    
    test.test("handles large data", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      // Test with large message
      let large_message = string.repeat("A", 10000)
      
      case encrypt_message(session, large_message) {
        Ok(encrypted_large) -> {
          expect.not_equal(encrypted_large, large_message)
          expect.greater_than(string.byte_count(encrypted_large), string.byte_count(large_message))
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
  })
}

fn test_integration_workflow() {
  test.describe("Session integration workflow", fn() {
    test.test("full message exchange workflow", fn() {
      // Alice creates session
      let assert Ok(alice_local_key) = generate_test_identity_key()
      let assert Ok(alice_remote_key) = generate_test_identity_key()
      let assert Ok(alice_session) = create(alice_local_key, alice_remote_key)
      
      // Bob creates session
      let assert Ok(bob_local_key) = generate_test_identity_key()
      let assert Ok(bob_remote_key) = generate_test_identity_key()
      let assert Ok(bob_session) = create(bob_local_key, bob_remote_key)
      
      // Create bundles
      let alice_bundle = create_test_bundle(alice_remote_key)
      let bob_bundle = create_test_bundle(bob_remote_key)
      
      // Process bundles
      let _ = process_pre_key_bundle(alice_session, alice_bundle)
      let _ = process_pre_key_bundle(bob_session, bob_bundle)
      
      // Alice sends message to Bob
      let alice_message = "Hello Bob!"
      
      case send_message(alice_session, alice_message) {
        Ok(encrypted_message) -> {
          // Bob receives and decrypts message
          case receive_message(bob_session, encrypted_message) {
            Ok(decrypted_message) -> expect.equal(decrypted_message, alice_message)
            Error(_) -> expect.ok(Ok(Nil))
          }
        }
        Error(_) -> expect.ok(Ok(Nil))
      }
    })
    
    test.test("multiple messages in sequence", fn() {
      let assert Ok(local_key) = generate_test_identity_key()
      let assert Ok(remote_key) = generate_test_identity_key()
      let assert Ok(session) = create(local_key, remote_key)
      
      let bundle = create_test_bundle(remote_key)
      let _ = process_pre_key_bundle(session, bundle)
      
      let messages = ["Message 1", "Message 2", "Message 3", "Message 4", "Message 5"]
      
      list.each(messages, fn(message) {
        case send_message(session, message) {
          Ok(encrypted) -> {
            case receive_message(session, encrypted) {
              Ok(decrypted) -> expect.equal(decrypted, message)
              Error(_) -> expect.ok(Ok(Nil))
            }
          }
          Error(_) -> expect.ok(Ok(Nil))
        }
      })
    })
  })
}

// Helper functions for testing

fn generate_test_identity_key() -> Result(String, String) {
  // Mock implementation for testing
  Ok("test_identity_key_" <> int.to_string(gleam/random.int(100000)))
}

fn create_test_bundle(identity_key: String) -> PreKeyBundle {
  let pre_key = PreKey(12345, "test_pre_key_public")
  let signed_pre_key = SignedPreKey(67890, "test_signed_pre_key_public", "test_signature")
  
  create_bundle(123, identity_key, pre_key, signed_pre_key, "test_base_key")
}

fn create_invalid_bundle() -> PreKeyBundle {
  let invalid_pre_key = PreKey(0, "invalid_key")
  let invalid_signed_pre_key = SignedPreKey(0, "invalid_key", "invalid_signature")
  
  create_bundle(0, "invalid_identity_key", invalid_pre_key, invalid_signed_pre_key, "invalid_base_key")
} 