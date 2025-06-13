import gleam/erlang
import gleam/option.{None, Some}
import gleam/result
import signal_protocol.{PreKey, PreKeyBundle, SignedPreKey}

/// Creates a new pre-key bundle.
pub fn create(
  registration_id: Int,
  identity_key: BitString,
  pre_key: PreKey,
  signed_pre_key: SignedPreKey,
  base_key: BitString,
) -> Result(PreKeyBundle, String) {
  // Validate input types
  case erlang.is_integer(registration_id) {
    False -> Error("Registration ID must be an integer")
    True -> {
      case erlang.is_bit_string(identity_key) {
        False -> Error("Identity key must be a bit string")
        True -> {
          case erlang.is_bit_string(base_key) {
            False -> Error("Base key must be a bit string")
            True -> {
              Ok(PreKeyBundle(
                registration_id: registration_id,
                identity_key: identity_key,
                pre_key: #(pre_key.key_id, pre_key.public_key),
                signed_pre_key: #(
                  signed_pre_key.key_id,
                  signed_pre_key.public_key,
                  signed_pre_key.signature,
                ),
                base_key: base_key,
              ))
            }
          }
        }
      }
    }
  }
}

/// Parses a pre-key bundle from its binary representation.
pub fn parse(bundle_binary: BitString) -> Result(PreKeyBundle, String) {
  case
    erlang.call_function("Elixir.SignalProtocol.PreKeyBundle", "parse", [
      bundle_binary,
    ])
  {
    Ok(#(Ok, bundle_map)) -> {
      case erlang.map_get(bundle_map, "registration_id") {
        Ok(registration_id) -> {
          case erlang.map_get(bundle_map, "identity_key") {
            Ok(identity_key) -> {
              case erlang.map_get(bundle_map, "pre_key") {
                Ok(pre_key) -> {
                  case erlang.map_get(bundle_map, "signed_pre_key") {
                    Ok(signed_pre_key) -> {
                      case erlang.map_get(bundle_map, "base_key") {
                        Ok(base_key) -> {
                          Ok(PreKeyBundle(
                            registration_id: registration_id,
                            identity_key: identity_key,
                            pre_key: pre_key,
                            signed_pre_key: signed_pre_key,
                            base_key: base_key,
                          ))
                        }
                        Error(_) -> Error("Invalid bundle: missing base key")
                      }
                    }
                    Error(_) -> Error("Invalid bundle: missing signed pre key")
                  }
                }
                Error(_) -> Error("Invalid bundle: missing pre key")
              }
            }
            Error(_) -> Error("Invalid bundle: missing identity key")
          }
        }
        Error(_) -> Error("Invalid bundle: missing registration ID")
      }
    }
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
}

/// Verifies the signature of a pre-key bundle.
pub fn verify_signature(bundle: PreKeyBundle) -> Result(Nil, String) {
  case
    erlang.call_function(
      "Elixir.SignalProtocol.PreKeyBundle",
      "verify_signature",
      [create_bundle_binary(bundle)],
    )
  {
    Ok(Ok) -> Ok(Nil)
    Ok(#(Error, reason)) -> Error(erlang.bit_string_to_string(reason))
    Error(e) -> Error(erlang.bit_string_to_string(e))
  }
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
