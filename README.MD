<b>Simple file cryptor written in Go.</b>

The cryptor uses AES for encrypt/decrypt and base64url for encoding/decoding.

Makefile:
```
make build - build binary file to the ./bin/ folder
```

Arguments
```
-k your encryption/decryption key, must be 128, 192 or 256 bits (required).
-i input file, anything that you want to encrypt/decrypt (required)
-a action, "encrypt" or "decrypt" (default "encrypt")
-o output file, not required, by default just log result into the console
```

Example:
```
Encrypt file and save it to encrypted.txt
./bin/cryptor -a encrypt -k XPC89EzZ6tthvHwz9UmoKZu3SE4YmzZ9 -i ./text.txt -o encrypted.txt

Decrypt file and save it to decrypted.txt
./bin/cryptor -a decrypt -k XPC89EzZ6tthvHwz9UmoKZu3SE4YmzZ9 -i ./encrypted.txt -o decrypted.txt
```