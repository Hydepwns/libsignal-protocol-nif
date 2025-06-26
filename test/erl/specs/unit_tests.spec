{config, "../config/unit.config"}.
{suites, "../unit/crypto", [signal_crypto_SUITE, crypto_wrapper_SUITE]}.
{suites, "../unit/protocol", [protocol_SUITE, session_SUITE]}.
{suites, "../unit/session", [session_management_SUITE, signal_session_SUITE]}.
{suites, "../unit/nif", [nif_functions_SUITE, nif_cache_SUITE, coverage_test_SUITE]}. 