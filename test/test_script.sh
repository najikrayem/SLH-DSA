# Run unit tests
build/test/slh_common_test
build/test/slh_sign_test
build/test/slh_hash_test
build/test/slh_ds_test


# Run basic sign verify test
build/example/cli/GenerateKeys secret public
build/example/cli/SignMessage secret build_script sig
build/example/cli/VerifySignature public build_script sig
