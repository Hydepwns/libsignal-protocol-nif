import gleam/erlang
import gleeunit
import gleeunit/should
import signal_protocol
import utils

pub fn main() {
  gleeunit.main()
}

pub fn test_generate_user_keys() {
  case utils.generate_user_keys() {
    Ok(#(identity_key_pair, pre_key, signed_pre_key)) -> {
      should.equal(erlang.is_bit_string(identity_key_pair.public_key), True)
      should.equal(erlang.is_bit_string(identity_key_pair.signature), True)
      should.equal(pre_key.key_id, 1)
      should.equal(erlang.is_bit_string(pre_key.public_key), True)
      should.equal(signed_pre_key.key_id, 1)
      should.equal(erlang.is_bit_string(signed_pre_key.public_key), True)
      should.equal(erlang.is_bit_string(signed_pre_key.signature), True)
    }
    Error(e) -> should.fail("Failed to generate user keys: " <> e)
  }
}

pub fn test_create_user_bundle() {
  case utils.generate_user_keys() {
    Ok(#(identity_key_pair, pre_key, signed_pre_key)) -> {
      case
        utils.create_user_bundle(1, identity_key_pair, pre_key, signed_pre_key)
      {
        Ok(bundle) -> {
          should.equal(bundle.registration_id, 1)
          should.equal(bundle.identity_key, identity_key_pair.public_key)
          should.equal(bundle.pre_key, #(pre_key.key_id, pre_key.public_key))
          should.equal(bundle.signed_pre_key, #(
            signed_pre_key.key_id,
            signed_pre_key.public_key,
            signed_pre_key.signature,
          ))
        }
        Error(e) -> should.fail("Failed to create user bundle: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate user keys: " <> e)
  }
}

pub fn test_establish_session() {
  case utils.generate_user_keys() {
    Ok(#(local_identity, local_pre_key, local_signed_pre_key)) -> {
      case utils.generate_user_keys() {
        Ok(#(remote_identity, remote_pre_key, remote_signed_pre_key)) -> {
          case
            utils.establish_session(
              local_identity.public_key,
              1,
              local_pre_key,
              local_signed_pre_key,
              remote_identity.public_key,
              2,
              remote_pre_key,
              remote_signed_pre_key,
            )
          {
            Ok(#(local_session, remote_session)) -> {
              should.equal(erlang.is_reference(local_session.reference), True)
              should.equal(erlang.is_reference(remote_session.reference), True)
            }
            Error(e) -> should.fail("Failed to establish session: " <> e)
          }
        }
        Error(e) -> should.fail("Failed to generate remote user keys: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate local user keys: " <> e)
  }
}

pub fn test_message_exchange() {
  case utils.generate_user_keys() {
    Ok(#(local_identity, local_pre_key, local_signed_pre_key)) -> {
      case utils.generate_user_keys() {
        Ok(#(remote_identity, remote_pre_key, remote_signed_pre_key)) -> {
          case
            utils.establish_session(
              local_identity.public_key,
              1,
              local_pre_key,
              local_signed_pre_key,
              remote_identity.public_key,
              2,
              remote_pre_key,
              remote_signed_pre_key,
            )
          {
            Ok(#(local_session, remote_session)) -> {
              let message = <<"Hello, Signal Protocol!">>
              case
                utils.exchange_messages(local_session, remote_session, message)
              {
                Ok(#(received_message, new_local_session, new_remote_session)) -> {
                  case
                    utils.verify_message_exchange(message, received_message)
                  {
                    Ok(Nil) -> {
                      should.equal(
                        erlang.is_reference(new_local_session.reference),
                        True,
                      )
                      should.equal(
                        erlang.is_reference(new_remote_session.reference),
                        True,
                      )
                    }
                    Error(e) ->
                      should.fail("Message verification failed: " <> e)
                  }
                }
                Error(e) -> should.fail("Failed to exchange messages: " <> e)
              }
            }
            Error(e) -> should.fail("Failed to establish session: " <> e)
          }
        }
        Error(e) -> should.fail("Failed to generate remote user keys: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate local user keys: " <> e)
  }
}

pub fn test_send_receive_with_session() {
  case utils.generate_user_keys() {
    Ok(#(local_identity, local_pre_key, local_signed_pre_key)) -> {
      case utils.generate_user_keys() {
        Ok(#(remote_identity, remote_pre_key, remote_signed_pre_key)) -> {
          case
            utils.establish_session(
              local_identity.public_key,
              1,
              local_pre_key,
              local_signed_pre_key,
              remote_identity.public_key,
              2,
              remote_pre_key,
              remote_signed_pre_key,
            )
          {
            Ok(#(local_session, remote_session)) -> {
              let message = <<"Hello, Signal Protocol!">>
              case utils.send_message_with_session(local_session, message) {
                Ok(#(ciphertext, new_local_session)) -> {
                  case
                    utils.receive_message_with_session(
                      remote_session,
                      ciphertext,
                    )
                  {
                    Ok(#(received_message, new_remote_session)) -> {
                      case
                        utils.verify_message_exchange(message, received_message)
                      {
                        Ok(Nil) -> {
                          should.equal(
                            erlang.is_reference(new_local_session.reference),
                            True,
                          )
                          should.equal(
                            erlang.is_reference(new_remote_session.reference),
                            True,
                          )
                        }
                        Error(e) ->
                          should.fail("Message verification failed: " <> e)
                      }
                    }
                    Error(e) -> should.fail("Failed to receive message: " <> e)
                  }
                }
                Error(e) -> should.fail("Failed to send message: " <> e)
              }
            }
            Error(e) -> should.fail("Failed to establish session: " <> e)
          }
        }
        Error(e) -> should.fail("Failed to generate remote user keys: " <> e)
      }
    }
    Error(e) -> should.fail("Failed to generate local user keys: " <> e)
  }
}
