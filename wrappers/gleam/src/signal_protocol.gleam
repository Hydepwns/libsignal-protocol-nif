import gleam/int

/// Represents a Signal Protocol session.
pub type Session {
  Session(reference: String)
}

/// Represents a pre-key bundle.
pub type PreKeyBundle {
  PreKeyBundle(
    registration_id: Int,
    identity_key: String,
    pre_key: #(Int, String),
    signed_pre_key: #(Int, String, String),
    base_key: String,
  )
}

/// Represents an identity key pair.
pub type IdentityKeyPair {
  IdentityKeyPair(public_key: String, signature: String)
}

/// Represents a pre-key.
pub type PreKey {
  PreKey(key_id: Int, public_key: String)
}

/// Represents a signed pre-key.
pub type SignedPreKey {
  SignedPreKey(key_id: Int, public_key: String, signature: String)
}

// --- FFI: libsignal_protocol_nif integration ---
@external(erlang, "libsignal_protocol_nif", "generate_identity_key_pair")
fn call_nif_generate_identity_key_pair() -> Result(#(String, String), String)

@external(erlang, "libsignal_protocol_nif", "generate_pre_key")
fn call_nif_generate_pre_key(key_id: Int) -> Result(#(Int, String), String)

@external(erlang, "libsignal_protocol_nif", "generate_signed_pre_key")
fn call_nif_generate_signed_pre_key(
  identity_key: String,
  key_id: Int,
) -> Result(#(Int, String, String), String)

@external(erlang, "libsignal_protocol_nif", "create_session")
fn call_nif_create_session(
  local_key: String,
  remote_key: String,
) -> Result(String, String)

@external(erlang, "libsignal_protocol_nif", "process_pre_key_bundle")
fn call_nif_process_pre_key_bundle(
  session_ref: String,
  bundle: String,
) -> Result(Nil, String)

@external(erlang, "libsignal_protocol_nif", "encrypt_message")
fn call_nif_encrypt_message(
  session_ref: String,
  message: String,
) -> Result(String, String)

@external(erlang, "libsignal_protocol_nif", "decrypt_message")
fn call_nif_decrypt_message(
  session_ref: String,
  ciphertext: String,
) -> Result(String, String)

// --- Public API ---

/// Generates a new identity key pair.
pub fn generate_identity_key_pair() -> Result(IdentityKeyPair, String) {
  case call_nif_generate_identity_key_pair() {
    Ok(#(public_key, signature)) -> Ok(IdentityKeyPair(public_key, signature))
    Error(reason) -> Error(reason)
  }
}

/// Generates a new pre-key with the given ID.
pub fn generate_pre_key(key_id: Int) -> Result(PreKey, String) {
  case call_nif_generate_pre_key(key_id) {
    Ok(#(key_id, public_key)) -> Ok(PreKey(key_id, public_key))
    Error(reason) -> Error(reason)
  }
}

/// Generates a new signed pre-key with the given ID, signed by the identity key.
pub fn generate_signed_pre_key(
  identity_key: String,
  key_id: Int,
) -> Result(SignedPreKey, String) {
  case call_nif_generate_signed_pre_key(identity_key, key_id) {
    Ok(#(key_id, public_key, signature)) ->
      Ok(SignedPreKey(key_id, public_key, signature))
    Error(reason) -> Error(reason)
  }
}

/// Creates a new session with the given local and remote identity keys.
pub fn create_session(
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
  case
    call_nif_process_pre_key_bundle(session_reference(session), bundle_binary)
  {
    Ok(Nil) -> Ok(Nil)
    Error(reason) -> Error(reason)
  }
}

/// Encrypts a message using the given session.
pub fn encrypt_message(
  session: Session,
  message: String,
) -> Result(String, String) {
  call_nif_encrypt_message(session_reference(session), message)
}

/// Decrypts a message using the given session.
pub fn decrypt_message(
  session: Session,
  ciphertext: String,
) -> Result(String, String) {
  call_nif_decrypt_message(session_reference(session), ciphertext)
}

/// Creates a new session and processes a pre-key bundle in one step.
pub fn create_and_process_bundle(
  local_identity_key: String,
  remote_identity_key: String,
  bundle: PreKeyBundle,
) -> Result(Session, String) {
  let session = create_session(local_identity_key, remote_identity_key)
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
  // This is a placeholder. You should implement the correct serialization as needed.
  // For now, we just concatenate the fields as a string for demonstration.
  bundle.registration_id |> int.to_string
  <> ":"
  <> bundle.identity_key
  <> ":"
  <> tuple_to_string(bundle.pre_key)
  <> ":"
  <> tuple_to_string3(bundle.signed_pre_key)
  <> ":"
  <> bundle.base_key
}

fn tuple_to_string(t: #(Int, String)) -> String {
  let #(i, s) = t
  int.to_string(i) <> ":" <> s
}

fn tuple_to_string3(t: #(Int, String, String)) -> String {
  let #(i, s1, s2) = t
  int.to_string(i) <> ":" <> s1 <> ":" <> s2
}
