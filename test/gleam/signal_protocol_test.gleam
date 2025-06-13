import gleam/erlang
import gleeunit
import gleeunit/should
import signal_protocol
import signal_protocol/pre_key_bundle
import signal_protocol/session

pub fn main() {
  gleeunit.main()
}

pub fn test_generate_identity_key_pair() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      should.equal(erlang.is_bit_string(identity_key_pair.public_key), True)
      should.equal(erlang.is_bit_string(identity_key_pair.signature), True)
    }
    Error(e) -> should.fail("Failed to generate identity key pair: " <> e)
  }
}

pub fn test_generate_pre_key() {
  case signal_protocol.generate_pre_key(1) {
    Ok(pre_key) -> {
      should.equal(pre_key.key_id, 1)
      should.equal(erlang.is_bit_string(pre_key.public_key), True)
    }
    Error(e) -> should.fail("Failed to generate pre-key: " <> e)
  }
}

pub fn test_generate_signed_pre_key() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      case
        signal_protocol.generate_signed_pre_key(identity_key_pair.public_key, 1)
      {
        Ok(signed_pre_key) -> {
          should.equal(signed_pre_key.key_id, 1)
          should.equal(erlang.is_bit_string(signed_pre_key.public_key), True)
          should.equal(erlang.is_bit_string(signed_pre_key.signature), True)
        }
        Error(e) -> should.fail("Failed to generate signed pre-key: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate identity key pair: " <> e)
  }
}

pub fn test_create_session() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(local_identity) -> {
      case signal_protocol.generate_identity_key_pair() {
        Ok(remote_identity) -> {
          case
            session.create(
              local_identity.public_key,
              remote_identity.public_key,
            )
          {
            Ok(session) -> {
              should.equal(erlang.is_reference(session.reference), True)
            }
            Error(e) -> should.fail("Failed to create session: " <> e)
          }
        }
        Error(e) ->
          should.fail("Failed to generate remote identity key pair: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate local identity key pair: " <> e)
  }
}

pub fn test_encrypt_decrypt_message() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(local_identity) -> {
      case signal_protocol.generate_identity_key_pair() {
        Ok(remote_identity) -> {
          case
            session.create(
              local_identity.public_key,
              remote_identity.public_key,
            )
          {
            Ok(session) -> {
              let message = <<"Hello, Signal Protocol!">>
              case session.encrypt_message(session, message) {
                Ok(ciphertext) -> {
                  case session.decrypt_message(session, ciphertext) {
                    Ok(decrypted) -> {
                      should.equal(decrypted, message)
                    }
                    Error(e) -> should.fail("Failed to decrypt message: " <> e)
                  }
                }
                Error(e) -> should.fail("Failed to encrypt message: " <> e)
              }
            }
            Error(e) -> should.fail("Failed to create session: " <> e)
          }
        }
        Error(e) ->
          should.fail("Failed to generate remote identity key pair: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate local identity key pair: " <> e)
  }
}

pub fn test_pre_key_bundle() {
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
              case
                pre_key_bundle.create(
                  1,
                  identity_key_pair.public_key,
                  pre_key,
                  signed_pre_key,
                  <<0:256>>,
                )
              {
                Ok(bundle) -> {
                  should.equal(bundle.registration_id, 1)
                  should.equal(
                    bundle.identity_key,
                    identity_key_pair.public_key,
                  )
                  should.equal(bundle.pre_key, #(
                    pre_key.key_id,
                    pre_key.public_key,
                  ))
                  should.equal(bundle.signed_pre_key, #(
                    signed_pre_key.key_id,
                    signed_pre_key.public_key,
                    signed_pre_key.signature,
                  ))
                }
                Error(e) ->
                  should.fail("Failed to create pre-key bundle: " <> e)
              }
            }
            Error(e) -> should.fail("Failed to generate signed pre-key: " <> e)
          }
        }
        Error(e) -> should.fail("Failed to generate pre-key: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate identity key pair: " <> e)
  }
}
