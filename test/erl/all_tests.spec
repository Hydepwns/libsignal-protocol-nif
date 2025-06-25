{config, "test.config"}.
{suites, "", [protocol_SUITE, signal_crypto_SUITE, session_management_SUITE]}.
{groups, "", protocol_SUITE, [fast]}.
{groups, "", signal_crypto_SUITE, [fast]}.
{groups, "", session_management_SUITE, [fast]}. 