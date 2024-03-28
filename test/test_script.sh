# Run unit tests
build/test/slh_common_test
build/test/slh_sign_test
build/test/slh_hash_test
build/test/slh_ds_test


# Run basic sign verify test
rm sec pub sig
build/example/cli/GenerateKeys sec pub
build/example/cli/SignMessage sec msg sig
build/example/cli/VerifySignature pub msg sig
