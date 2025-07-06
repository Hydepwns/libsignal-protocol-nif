import gleam/int
import signal_protocol.{type PreKeyBundle, type Session, Session}

// --- FFI: libsignal_protocol_nif integration ---
@external(erlang, "libsignal_protocol_nif", "create_session")
fn call_nif_create_session(
  local_key: String,
  remote_key: String,
) -> Result(String, String)

@external(erlang, "libsignal_protocol_nif", "process_pre_key_bundle")
fn call_nif_process_bundle(
  session_ref: String,
  bundle: String,
) -> Result(Nil, String)

@external(erlang, "libsignal_protocol_nif", "encrypt_message")
fn call_nif_encrypt(
  session_ref: String,
  message: String,
) -> Result(String, String)

@external(erlang, "libsignal_protocol_nif", "decrypt_message")
fn call_nif_decrypt(
  session_ref: String,
  ciphertext: String,
) -> Result(String, String)

/// Creates a new session with the given local and remote identity keys.
pub fn create(
  local_identity_key: String,
  remote_identity_key: String,
) -> Result(Session, String) {
  case call_nif_create_session(local_identity_key, remote_identity_key) {
    Ok(reference) -> Ok(Session(reference))
    Error(reason) -> Error(reason)
  }
}

/// Processes a pre-key bundle to establish a session.
pub fn process_pre_key_bundle(
  session: Session,
  bundle: PreKeyBundle,
) -> Result(Nil, String) {
  let bundle_binary = create_bundle_binary(bundle)
  case call_nif_process_bundle(session_reference(session), bundle_binary) {
    Ok(Nil) -> Ok(Nil)
    Error(reason) -> Error(reason)
  }
}

/// Encrypts a message using the given session.
pub fn encrypt_message(
  session: Session,
  message: String,
) -> Result(String, String) {
  call_nif_encrypt(session_reference(session), message)
}

/// Decrypts a message using the given session.
pub fn decrypt_message(
  session: Session,
  ciphertext: String,
) -> Result(String, String) {
  call_nif_decrypt(session_reference(session), ciphertext)
}

/// Creates a new session and processes a pre-key bundle in one step.
pub fn create_and_process_bundle(
  local_identity_key: String,
  remote_identity_key: String,
  bundle: PreKeyBundle,
) -> Result(Session, String) {
  let session = create(local_identity_key, remote_identity_key)
  case session {
    Ok(session) -> {
      case process_pre_key_bundle(session, bundle) {
        Ok(Nil) -> Ok(session)
        Error(e) -> Error(e)
      }
    }
    Error(e) -> Error(e)
  }
}

/// Sends a message through a session, handling encryption.
pub fn send_message(session: Session, message: String) -> Result(String, String) {
  encrypt_message(session, message)
}

/// Receives a message through a session, handling decryption.
pub fn receive_message(
  session: Session,
  ciphertext: String,
) -> Result(String, String) {
  decrypt_message(session, ciphertext)
}

// Helper function to extract the reference from a Session
fn session_reference(session: Session) -> String {
  case session {
    Session(reference) -> reference
  }
}

// Helper function to create a binary representation of a pre-key bundle
fn create_bundle_binary(bundle: PreKeyBundle) -> String {
  let #(pre_key_id, pre_key_public) = bundle.pre_key
  let #(signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
    bundle.signed_pre_key
  // This is a placeholder. You should implement the correct serialization as needed.
  // For now, we just concatenate the fields as a string for demonstration.
  bundle.registration_id |> int.to_string
  <> ":"
  <> bundle.identity_key
  <> ":"
  <> pre_key_id |> int.to_string
  <> ","
  <> pre_key_public
  <> ":"
  <> signed_pre_key_id |> int.to_string
  <> ","
  <> signed_pre_key_public
  <> ","
  <> signed_pre_key_signature
  <> ":"
  <> bundle.base_key
}
