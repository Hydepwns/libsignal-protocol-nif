import gleam/erlang
import gleam/option.{None, Some}
import gleam/result
import signal_protocol
import signal_protocol/pre_key_bundle
import signal_protocol/session

/// Generates a complete set of keys for a new user.
pub fn generate_user_keys() -> Result(
  #(
    signal_protocol.IdentityKeyPair,
    signal_protocol.PreKey,
    signal_protocol.SignedPreKey,
  ),
  String,
) {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      case signal_protocol.generate_pre_key(1) {
        Ok(pre_key) -> {
          case
            signal_protocol.generate_signed_pre_key(
              identity_key_pair.public_key,
              1,
            )
          {
            Ok(signed_pre_key) -> {
              Ok(#(identity_key_pair, pre_key, signed_pre_key))
            }
            Error(e) -> Error("Failed to generate signed pre-key: " <> e)
          }
        }
        Error(e) -> Error("Failed to generate pre-key: " <> e)
      }
    }
    Error(e) -> Error("Failed to generate identity key pair: " <> e)
  }
}

/// Creates a pre-key bundle from user keys.
pub fn create_user_bundle(
  registration_id: Int,
  identity_key_pair: signal_protocol.IdentityKeyPair,
  pre_key: signal_protocol.PreKey,
  signed_pre_key: signal_protocol.SignedPreKey,
) -> Result(signal_protocol.PreKeyBundle, String) {
  pre_key_bundle.create(
    registration_id,
    identity_key_pair.public_key,
    pre_key,
    signed_pre_key,
    <<0:256>>,
    // Base key will be generated during session creation
  )
}

/// Establishes a session between two users using their pre-key bundles.
pub fn establish_session(
  local_identity_key: BitString,
  local_registration_id: Int,
  local_pre_key: signal_protocol.PreKey,
  local_signed_pre_key: signal_protocol.SignedPreKey,
  remote_identity_key: BitString,
  remote_registration_id: Int,
  remote_pre_key: signal_protocol.PreKey,
  remote_signed_pre_key: signal_protocol.SignedPreKey,
) -> Result(#(session.Session, session.Session), String) {
  // Create local bundle
  case
    create_user_bundle(
      local_registration_id,
      signal_protocol.IdentityKeyPair(
        public_key: local_identity_key,
        signature: <<>>,
      ),
      local_pre_key,
      local_signed_pre_key,
    )
  {
    Ok(local_bundle) -> {
      // Create remote bundle
      case
        create_user_bundle(
          remote_registration_id,
          signal_protocol.IdentityKeyPair(
            public_key: remote_identity_key,
            signature: <<>>,
          ),
          remote_pre_key,
          remote_signed_pre_key,
        )
      {
        Ok(remote_bundle) -> {
          // Create local session
          case session.create(local_identity_key, remote_identity_key) {
            Ok(local_session) -> {
              // Create remote session
              case session.create(remote_identity_key, local_identity_key) {
                Ok(remote_session) -> {
                  // Process bundles
                  case
                    session.process_pre_key_bundle(local_session, remote_bundle)
                  {
                    Ok(Nil) -> {
                      case
                        session.process_pre_key_bundle(
                          remote_session,
                          local_bundle,
                        )
                      {
                        Ok(Nil) -> {
                          Ok(#(local_session, remote_session))
                        }
                        Error(e) ->
                          Error(
                            "Failed to process local bundle on remote session: "
                            <> e,
                          )
                      }
                    }
                    Error(e) ->
                      Error(
                        "Failed to process remote bundle on local session: "
                        <> e,
                      )
                  }
                }
                Error(e) -> Error("Failed to create remote session: " <> e)
              }
            }
            Error(e) -> Error("Failed to create local session: " <> e)
          }
        }
        Error(e) -> Error("Failed to create remote bundle: " <> e)
      }
    }
    Error(e) -> Error("Failed to create local bundle: " <> e)
  }
}

/// Sends a message and returns both the ciphertext and the session.
pub fn send_message_with_session(
  session: session.Session,
  message: BitString,
) -> Result(#(BitString, session.Session), String) {
  case session.encrypt_message(session, message) {
    Ok(ciphertext) -> {
      Ok(#(ciphertext, session))
    }
    Error(e) -> Error("Failed to encrypt message: " <> e)
  }
}

/// Receives a message and returns both the plaintext and the session.
pub fn receive_message_with_session(
  session: session.Session,
  ciphertext: BitString,
) -> Result(#(BitString, session.Session), String) {
  case session.decrypt_message(session, ciphertext) {
    Ok(message) -> {
      Ok(#(message, session))
    }
    Error(e) -> Error("Failed to decrypt message: " <> e)
  }
}

/// Performs a complete message exchange between two sessions.
pub fn exchange_messages(
  local_session: session.Session,
  remote_session: session.Session,
  message: BitString,
) -> Result(#(BitString, session.Session, session.Session), String) {
  case send_message_with_session(local_session, message) {
    Ok(#(ciphertext, local_session)) -> {
      case receive_message_with_session(remote_session, ciphertext) {
        Ok(#(received_message, remote_session)) -> {
          Ok(#(received_message, local_session, remote_session))
        }
        Error(e) -> Error("Failed to receive message: " <> e)
      }
    }
    Error(e) -> Error("Failed to send message: " <> e)
  }
}

/// Verifies that a message exchange was successful by comparing the sent and received messages.
pub fn verify_message_exchange(
  sent_message: BitString,
  received_message: BitString,
) -> Result(Nil, String) {
  case sent_message == received_message {
    True -> Ok(Nil)
    False ->
      Error(
        "Message verification failed: sent and received messages do not match",
      )
  }
}
