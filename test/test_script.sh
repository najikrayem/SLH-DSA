# Run unit tests
build/test/slh_common_test
build/test/slh_sign_test
build/test/slh_hash_test
build/test/slh_ds_test


# Run basic sign verify test
mkdir -p build/test_temp
cd build/test_temp
cp ../../test/test_data/msg msg
#rm sec pub sig
echo
echo "Generating keys..."
../example/cli/GenerateKeys sec pub

echo
echo "Signing message..."
../example/cli/SignMessage sec msg sig

echo
echo "Verifying Signature..."
echo
../example/cli/VerifySignature pub msg sig

echo
echo "------------------"
echo "Testing IFS Verifier..."
echo
../example/qnx_ifs_verify_mount/IFSVerifyMount pub msg sig
cd ../..


