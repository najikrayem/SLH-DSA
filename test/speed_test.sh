# # Create 3 files with random data
# dd if=/dev/urandom of=file1.bin bs=1M count=1
# dd if=/dev/urandom of=file2.bin bs=1M count=10
# dd if=/dev/urandom of=file3.bin bs=1M count=100

sleep 1

# Show files
ls -l

echo
echo "GENERATE KEYS: "
time ./GenerateKeys sec pub
sleep 1
time ./GenerateKeys_A72 sec_a72 pub_a72
sleep 1

echo
echo "SIGN FILES: "
time ./SignMessage sec file1.bin sig1
sleep 1
time ./SignMessage_A72 sec file1.bin sig1_a72
sleep 1

time ./SignMessage sec file2.bin sig2
sleep 1
time ./SignMessage_A72 sec file2.bin sig2_a72
sleep 1

time ./SignMessage sec file3.bin sig3
sleep 1
time ./SignMessage_A72 sec file3.bin sig3_a72
sleep 1

# Ensure that the files are the same
# diff sig1 sig1_a72
# diff sig2 sig2_a72
# diff sig3 sig3_a72

echo
echo "VERIFY FILES: "
time ./VerifySignature pub file1.bin sig1
sleep 1
time ./VerifySignature_A72 pub file1.bin sig1_a72
sleep 1

time ./VerifySignature pub file2.bin sig2
sleep 1
time ./VerifySignature_A72 pub file2.bin sig2_a72
sleep 1

time ./VerifySignature pub file3.bin sig3
sleep 1
time ./VerifySignature_A72 pub file3.bin sig3_a72
sleep 1