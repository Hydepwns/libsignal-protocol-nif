import gleam/int
import signal_protocol.{
  type PreKey, type PreKeyBundle, type SignedPreKey, PreKeyBundle,
}

/// Creates a new pre-key bundle.
pub fn create(
  registration_id: Int,
  identity_key: String,
  pre_key: PreKey,
  signed_pre_key: SignedPreKey,
  base_key: String,
) -> Result(PreKeyBundle, String) {
  Ok(PreKeyBundle(
    registration_id,
    identity_key,
    #(pre_key.key_id, pre_key.public_key),
    #(
      signed_pre_key.key_id,
      signed_pre_key.public_key,
      signed_pre_key.signature,
    ),
    base_key,
  ))
}

// --- FFI: Elixir.SignalProtocol.PreKeyBundle integration ---
@external(erlang, "Elixir.SignalProtocol.PreKeyBundle", "parse")
fn call_elixir_parse(bundle_binary: String) -> Result(PreKeyBundle, String)

@external(erlang, "Elixir.SignalProtocol.PreKeyBundle", "verify_signature")
fn call_elixir_verify_signature(bundle_binary: String) -> Result(Nil, String)

/// Parses a pre-key bundle from its binary representation.
pub fn parse(bundle_binary: String) -> Result(PreKeyBundle, String) {
  call_elixir_parse(bundle_binary)
}

/// Verifies the signature of a pre-key bundle.
pub fn verify_signature(bundle: PreKeyBundle) -> Result(Nil, String) {
  let bundle_binary = create_bundle_binary(bundle)
  call_elixir_verify_signature(bundle_binary)
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
