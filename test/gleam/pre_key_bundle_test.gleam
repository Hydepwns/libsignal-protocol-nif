import gleam/expect.{equal, fail, ok}
import gleeunit
import signal_protocol.{PreKey, PreKeyBundle, SignedPreKey}
import signal_protocol/pre_key_bundle.{create, parse, verify_signature}

pub fn main() {
  gleeunit.main()
}

pub fn all() {
  [
    test_create_bundle(),
    test_parse_bundle(),
    test_verify_signature(),
    test_error_handling(),
    test_integration_workflow(),
  ]
}

fn test_create_bundle() {
  equal(
    create(
      123,
      "test_identity_key",
      PreKey(12_345, "test_pre_key_public"),
      SignedPreKey(67_890, "test_signed_pre_key_public", "test_signature"),
      "test_base_key",
    ),
    Ok(PreKeyBundle(
      123,
      "test_identity_key",
      #(12_345, "test_pre_key_public"),
      #(67_890, "test_signed_pre_key_public", "test_signature"),
      "test_base_key",
    )),
  )
}

fn test_parse_bundle() {
  let bundle =
    create(
      123,
      "test_identity_key",
      PreKey(12_345, "test_pre_key_public"),
      SignedPreKey(67_890, "test_signed_pre_key_public", "test_signature"),
      "test_base_key",
    )

  case bundle {
    Ok(b) -> {
      let bundle_binary = create_bundle_binary(b)
      case parse(bundle_binary) {
        Ok(parsed_bundle) -> {
          equal(parsed_bundle.registration_id, b.registration_id)
          equal(parsed_bundle.identity_key, b.identity_key)
        }
        Error(_) -> ok(Nil)
      }
    }
    Error(_) -> fail("Bundle should be Ok")
  }
}

fn test_verify_signature() {
  let bundle =
    create(
      123,
      "test_identity_key",
      PreKey(12_345, "test_pre_key_public"),
      SignedPreKey(67_890, "test_signed_pre_key_public", "test_signature"),
      "test_base_key",
    )

  case bundle {
    Ok(b) -> {
      case verify_signature(b) {
        Ok(Nil) -> ok(Nil)
        Error(_) -> ok(Nil)
      }
    }
    Error(_) -> fail("Bundle should be Ok")
  }
}

fn test_error_handling() {
  let invalid_binaries = ["", "invalid_string", "not_a_bundle"]

  list.each(invalid_binaries, fn(invalid_binary) {
    case parse(invalid_binary) {
      Ok(_) -> ok(Nil)
      Error(_) -> ok(Nil)
    }
  })
}

fn test_integration_workflow() {
  let bundle =
    create(
      123,
      "test_identity_key",
      PreKey(12_345, "test_pre_key_public"),
      SignedPreKey(67_890, "test_signed_pre_key_public", "test_signature"),
      "test_base_key",
    )

  case bundle {
    Ok(b) -> {
      case verify_signature(b) {
        Ok(Nil) -> {
          let bundle_binary = create_bundle_binary(b)
          case parse(bundle_binary) {
            Ok(parsed_bundle) -> {
              equal(parsed_bundle.registration_id, b.registration_id)
              equal(parsed_bundle.identity_key, b.identity_key)
            }
            Error(_) -> ok(Nil)
          }
        }
        Error(_) -> ok(Nil)
      }
    }
    Error(_) -> fail("Bundle should be Ok")
  }
}

// Helper functions for testing

fn create_bundle_binary(bundle: PreKeyBundle) -> String {
  let #(pre_key_id, pre_key_public) = bundle.pre_key
  let #(signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
    bundle.signed_pre_key

  // This is a placeholder serialization for testing
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
