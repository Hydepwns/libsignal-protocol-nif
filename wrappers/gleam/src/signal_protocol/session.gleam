import gleam/erlang
import gleam/option.{None, Some}
import gleam/result
import signal_protocol.{PreKeyBundle, Session}

/// Creates a new session with the given local and remote identity keys.
pub fn create(
  local_identity_key: BitString,
  remote_identity_key: BitString,
) -> Result(Session, String) {
  case
    erlang.call_function("Elixir.SignalProtocol.Session", "create", [
      local_identity_key,
      remote_identity_key,
    ])
  {
    Ok(#(Ok, session)) -> Ok(Session(reference: session))
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
}

/// Processes a pre-key bundle to establish a session.
pub fn process_pre_key_bundle(
  session: Session,
  bundle: PreKeyBundle,
) -> Result(Nil, String) {
  let bundle_binary = create_bundle_binary(bundle)
  case
    erlang.call_function(
      "Elixir.SignalProtocol.Session",
      "process_pre_key_bundle",
      [session.reference, bundle_binary],
    )
  {
    Ok(Ok) -> Ok(Nil)
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
}

/// Encrypts a message using the given session.
pub fn encrypt_message(
  session: Session,
  message: BitString,
) -> Result(BitString, String) {
  case
    erlang.call_function("Elixir.SignalProtocol.Session", "encrypt_message", [
      session.reference,
      message,
    ])
  {
    Ok(#(Ok, ciphertext)) -> Ok(ciphertext)
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
}

/// Decrypts a message using the given session.
pub fn decrypt_message(
  session: Session,
  ciphertext: BitString,
) -> Result(BitString, String) {
  case
    erlang.call_function("Elixir.SignalProtocol.Session", "decrypt_message", [
      session.reference,
      ciphertext,
    ])
  {
    Ok(#(Ok, message)) -> Ok(message)
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
}

/// Creates a new session and processes a pre-key bundle in one step.
pub fn create_and_process_bundle(
  local_identity_key: BitString,
  remote_identity_key: BitString,
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
pub fn send_message(
  session: Session,
  message: BitString,
) -> Result(BitString, String) {
  encrypt_message(session, message)
}

/// Receives a message through a session, handling decryption.
pub fn receive_message(
  session: Session,
  ciphertext: BitString,
) -> Result(BitString, String) {
  decrypt_message(session, ciphertext)
}

// Helper function to create a binary representation of a pre-key bundle
fn create_bundle_binary(bundle: PreKeyBundle) -> BitString {
  let #(pre_key_id, pre_key_public) = bundle.pre_key
  let #(signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
    bundle.signed_pre_key

  erlang.bit_string_concat([
    <<1:8>>,
    // version
    <<bundle.registration_id:32>>,
    <<pre_key_id:32>>,
    <<signed_pre_key_id:32>>,
    bundle.identity_key,
    pre_key_public,
    signed_pre_key_public,
    signed_pre_key_signature,
    bundle.base_key,
  ])
}
