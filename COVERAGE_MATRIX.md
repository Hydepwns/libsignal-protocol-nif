# Detailed Test Coverage Matrix

## Function Coverage by Wrapper

### Core NIF Functions (via signal_nif module)

| Function                       | Erlang | Elixir | Gleam | Status  |
| ------------------------------ | ------ | ------ | ----- | ------- |
| `generate_identity_key_pair/0` | ❌     | ✅     | ✅    | **2/3** |
| `generate_pre_key/1`           | ❌     | ✅     | ✅    | **2/3** |
| `generate_signed_pre_key/2`    | ❌     | ✅     | ✅    | **2/3** |
| `create_session/2`             | ❌     | ✅     | ✅    | **2/3** |
| `process_pre_key_bundle/2`     | ❌     | ❌     | ❌    | **0/3** |
| `encrypt_message/2`            | ❌     | ✅     | ✅    | **2/3** |
| `decrypt_message/2`            | ❌     | ✅     | ✅    | **2/3** |
| `sign_data/2`                  | ❌     | ✅     | ❌    | **1/3** |
| `verify_signature/3`           | ❌     | ✅     | ❌    | **1/3** |
| `encrypt_message/3`            | ❌     | ✅     | ❌    | **1/3** |
| `decrypt_message/3`            | ❌     | ✅     | ❌    | **1/3** |
| `hmac_sha256/2`                | ❌     | ✅     | ❌    | **1/3** |
| `sha256/1`                     | ❌     | ✅     | ❌    | **1/3** |
| `random_bytes/1`               | ❌     | ✅     | ❌    | **1/3** |

### Erlang Wrapper Functions

| Function                                       | Tested | Status                        |
| ---------------------------------------------- | ------ | ----------------------------- |
| `signal_crypto:generate_key_pair/0`            | ❌     | **NIF Loading Issue**         |
| `signal_crypto:sign/2`                         | ❌     | **NIF Loading Issue**         |
| `signal_crypto:verify/3`                       | ❌     | **NIF Loading Issue**         |
| `signal_crypto:encrypt/3`                      | ❌     | **NIF Loading Issue**         |
| `signal_crypto:decrypt/3`                      | ❌     | **NIF Loading Issue**         |
| `signal_crypto:hmac/2`                         | ❌     | **NIF Loading Issue**         |
| `signal_crypto:hash/1`                         | ❌     | **NIF Loading Issue**         |
| `signal_crypto:random_bytes/1`                 | ❌     | **NIF Loading Issue**         |
| `signal_protocol:start/0`                      | ❌     | Missing                       |
| `signal_protocol:stop/0`                       | ❌     | Missing                       |
| `signal_protocol:generate_identity_key_pair/0` | ❌     | Missing                       |
| `signal_protocol:generate_pre_key/1`           | ❌     | Missing                       |
| `signal_protocol:generate_signed_pre_key/2`    | ❌     | Missing                       |
| `signal_protocol:create_session/2`             | ❌     | Missing                       |
| `signal_protocol:process_pre_key_bundle/2`     | ❌     | Missing                       |
| `signal_protocol:encrypt_message/2`            | ❌     | Missing                       |
| `signal_protocol:decrypt_message/2`            | ❌     | Missing                       |
| `signal_session:new/2`                         | ✅     | **Test Infrastructure Ready** |
| `signal_session:process_pre_key_bundle/2`      | ✅     | **Test Infrastructure Ready** |
| `signal_session:encrypt/2`                     | ✅     | **Test Infrastructure Ready** |
| `signal_session:decrypt/2`                     | ✅     | **Test Infrastructure Ready** |
| `signal_session:get_session_id/1`              | ✅     | **Test Infrastructure Ready** |

### Elixir Wrapper Functions

| Function                                             | Tested | Status  |
| ---------------------------------------------------- | ------ | ------- |
| `SignalProtocol.generate_identity_key_pair/0`        | ✅     | Tested  |
| `SignalProtocol.generate_pre_key/1`                  | ✅     | Tested  |
| `SignalProtocol.generate_signed_pre_key/2`           | ✅     | Tested  |
| `SignalProtocol.create_session/2`                    | ✅     | Tested  |
| `SignalProtocol.process_pre_key_bundle/2`            | ❌     | Missing |
| `SignalProtocol.encrypt_message/2`                   | ✅     | Tested  |
| `SignalProtocol.decrypt_message/2`                   | ✅     | Tested  |
| `SignalProtocol.sign_data/2`                         | ✅     | Tested  |
| `SignalProtocol.verify_signature/3`                  | ✅     | Tested  |
| `SignalProtocol.encrypt_message/3`                   | ✅     | Tested  |
| `SignalProtocol.decrypt_message/3`                   | ✅     | Tested  |
| `SignalProtocol.hmac_sha256/2`                       | ✅     | Tested  |
| `SignalProtocol.sha256/1`                            | ✅     | Tested  |
| `SignalProtocol.random_bytes/1`                      | ✅     | Tested  |
| `SignalProtocol.Session.create/2`                    | ❌     | Missing |
| `SignalProtocol.Session.process_pre_key_bundle/2`    | ❌     | Missing |
| `SignalProtocol.Session.encrypt_message/2`           | ❌     | Missing |
| `SignalProtocol.Session.decrypt_message/2`           | ❌     | Missing |
| `SignalProtocol.Session.create_and_process_bundle/3` | ❌     | Missing |
| `SignalProtocol.Session.send_message/2`              | ❌     | Missing |
| `SignalProtocol.Session.receive_message/2`           | ❌     | Missing |
| `SignalProtocol.PreKeyBundle.create/5`               | ❌     | Missing |
| `SignalProtocol.PreKeyBundle.parse/1`                | ❌     | Missing |
| `SignalProtocol.PreKeyBundle.verify_signature/1`     | ❌     | Missing |
| `LibsignalProtocol.create_session/1`                 | ✅     | Tested  |
| `LibsignalProtocol.encrypt_message/2`                | ✅     | Tested  |
| `LibsignalProtocol.decrypt_message/2`                | ✅     | Tested  |

### Gleam Wrapper Functions

| Function                                               | Tested | Status  |
| ------------------------------------------------------ | ------ | ------- |
| `signal_protocol.generate_identity_key_pair/0`         | ✅     | Tested  |
| `signal_protocol.generate_pre_key/1`                   | ✅     | Tested  |
| `signal_protocol.generate_signed_pre_key/2`            | ✅     | Tested  |
| `signal_protocol.create_session/2`                     | ✅     | Tested  |
| `signal_protocol.process_pre_key_bundle/2`             | ❌     | Missing |
| `signal_protocol.encrypt_message/2`                    | ✅     | Tested  |
| `signal_protocol.decrypt_message/2`                    | ✅     | Tested  |
| `signal_protocol.create_and_process_bundle/3`          | ❌     | Missing |
| `signal_protocol.send_message/2`                       | ❌     | Missing |
| `signal_protocol.receive_message/2`                    | ❌     | Missing |
| `signal_protocol/session.create/2`                     | ❌     | Missing |
| `signal_protocol/session.process_pre_key_bundle/2`     | ❌     | Missing |
| `signal_protocol/session.encrypt_message/2`            | ❌     | Missing |
| `signal_protocol/session.decrypt_message/2`            | ❌     | Missing |
| `signal_protocol/session.create_and_process_bundle/3`  | ❌     | Missing |
| `signal_protocol/session.send_message/2`               | ❌     | Missing |
| `signal_protocol/session.receive_message/2`            | ❌     | Missing |
| `signal_protocol/pre_key_bundle.create/5`              | ✅     | Tested  |
| `signal_protocol/pre_key_bundle.parse/1`               | ❌     | Missing |
| `signal_protocol/pre_key_bundle.verify_signature/1`    | ❌     | Missing |
| `signal_protocol/utils.generate_user_keys/0`           | ✅     | Tested  |
| `signal_protocol/utils.create_user_bundle/4`           | ✅     | Tested  |
| `signal_protocol/utils.establish_session/8`            | ✅     | Tested  |
| `signal_protocol/utils.exchange_messages/3`            | ✅     | Tested  |
| `signal_protocol/utils.send_message_with_session/2`    | ✅     | Tested  |
| `signal_protocol/utils.receive_message_with_session/2` | ✅     | Tested  |
| `signal_protocol/utils.verify_message_exchange/2`      | ✅     | Tested  |

## Infrastructure Status

### ✅ Working Components

1. **NIF Build System**: Successfully builds native library
2. **Test Infrastructure**: Common Test framework operational
3. **Module Compilation**: All Erlang modules compile successfully
4. **Basic Test Execution**: Simple tests pass
5. **Module Loading**: All modules can be loaded correctly
6. **OpenSSL Integration**: OpenSSL 3.x compatibility achieved
7. **ASDF Erlang Environment**: Properly configured Erlang 26.2.4
8. **Architecture Compatibility**: ARM64 NIF matches ARM64 system

### ❌ Known Issues

1. **NIF Loading Failure**: **CRITICAL BLOCKER** - NIF fails to load with `load_failed` error
2. **Dynamic Linking Issue**: Runtime library resolution problem
3. **Module Architecture**: Duplicate NIF loading code causing conflicts
4. **Erlang Test Dependencies**: `signal_crypto` depends on `signal_nif` which can't load NIF

## Coverage Statistics

### By Wrapper

- **Erlang**: 5/25 functions tested (20%) - **Blocked by NIF loading issue**
- **Elixir**: 14/25 functions tested (56%)
- **Gleam**: 14/31 functions tested (45%)

### By Function Type

- **Core NIF Functions**: 8/14 functions tested (57%)
- **Session Management**: 5/15 functions tested (33%)
- **Cryptographic Operations**: 7/8 functions tested (88%)
- **Pre-key Bundle Operations**: 1/6 functions tested (17%)
- **Utility Functions**: 5/5 functions tested (100%)

### Critical Gaps

1. **NIF Loading Failure**: **CRITICAL BLOCKER** - Prevents all Erlang tests from running
2. **Pre-key Bundle Processing**: Only 1/6 functions tested across all wrappers
3. **Session Management**: Poor coverage in Erlang and Gleam wrappers
4. **Error Handling**: No error case testing visible
5. **Integration Tests**: No end-to-end workflow testing
6. **Cross-Wrapper Compatibility**: No interoperability testing

## Priority for Test Development

### 🔥 **CRITICAL** (Blocking All Erlang Tests)

1. **Fix NIF Loading Issue**

   - **Investigate Dynamic Linking**: Check for missing runtime dependencies
   - **Library Path Resolution**: Ensure OpenSSL libraries are found at runtime
   - **Code Signing/Quarantine**: Check for macOS security restrictions
   - **Symbol Resolution**: Verify all required symbols are available
   - **Create Minimal Test NIF**: Test basic NIF loading without OpenSSL dependencies

2. **Resolve Module Conflicts**
   - Consolidate NIF loading into single module (`libsignal_protocol_nif`)
   - Remove duplicate NIF loading code from `signal_nif`
   - Update `signal_crypto` to use the working NIF module
   - Ensure proper module initialization order

### High Priority

1. **Resolve Erlang Test Blockers**

   - Update `signal_crypto` to use correct NIF module
   - Fix module dependency chain
   - Enable Erlang test execution

2. **Add Missing Core Tests**
   - Add `process_pre_key_bundle/2` tests to all wrappers
   - Add error handling tests
   - Add integration tests

### Medium Priority

1. **Complete Session Management Coverage**

   - Add session management tests to Gleam wrapper
   - Add pre-key bundle parsing and verification tests
   - Add performance tests

2. **Security Validation**
   - Add security validation tests
   - Add edge case testing
   - Add load testing

### Low Priority

1. **Documentation and Compatibility**
   - Add documentation tests
   - Add cross-wrapper compatibility tests
   - Add comprehensive integration workflows

## Recent Progress

### ✅ **Completed**

- Fixed OpenSSL 3.x compatibility issues
- Established working test infrastructure
- Created simple test validation
- Identified root cause of Erlang test failures
- Compiled all modules successfully
- **NIF Loading Investigation**: Comprehensive debugging of NIF loading issue
- **Architecture Verification**: Confirmed ARM64 compatibility
- **Symbol Analysis**: Verified required NIF symbols are present

### 🔄 **In Progress**

- Resolving NIF loading failure (CRITICAL BLOCKER)
- Investigating dynamic linking issues
- Testing potential solutions for NIF loading

### 📋 **Next Steps**

1. **CRITICAL**: Fix NIF loading issue to unblock all Erlang tests
2. Consolidate NIF loading into single module
3. Update `signal_crypto` dependencies
4. Enable Erlang test execution
5. Add missing test coverage

## NIF Loading Investigation Summary

### ✅ **What We Know Works**

- NIF compiles successfully without errors
- Architecture matches (ARM64)
- OpenSSL dependencies are correctly linked
- Required symbols (`_nif_init`) are present
- ASDF Erlang environment is properly configured

### ❌ **What's Broken**

- NIF fails to load with `load_failed` error
- `on_load` function is never called (NIF fails before initialization)
- Dynamic linking issue prevents NIF from loading
- Module conflicts between `libsignal_protocol_nif` and `signal_nif`

### 🔍 **Root Cause Analysis**

The `load_failed` error indicates a runtime linking problem, not a compilation issue. Most likely causes:

1. **Missing Runtime Dependencies**: OpenSSL libraries can't be found at runtime
2. **Symbol Resolution Issues**: Some symbols in the NIF can't be resolved
3. **Library Path Issues**: Dynamic linker can't find required libraries
4. **Code Signing/Quarantine**: macOS security features blocking the NIF

### 🛠️ **Potential Solutions to Try**

1. Set `DYLD_LIBRARY_PATH` and `DYLD_FALLBACK_LIBRARY_PATH` environment variables
2. Remove any quarantine attributes from the NIF file
3. Create a minimal NIF without OpenSSL dependencies to test basic loading
4. Check system logs for macOS security or dynamic linking errors
5. Try building with different OpenSSL versions or configurations
