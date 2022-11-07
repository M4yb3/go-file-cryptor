package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"os"
)

func GetTextFromFile(filepath string) ([]byte, error) {
	// Open the file
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	// Read the file
	plaintext, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)

	return encrypted, nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	action := flag.String("a", "encrypt", "encrypt or decrypt")
	key := flag.String("k", "", "aes key")
	filepath := flag.String("i", "", "path to the file that need to be encrypted or decrypted")
	output := flag.String("o", "", "name of output file")

	flag.Parse()

	data, err := GetTextFromFile(*filepath)
	if err != nil {
		log.Fatal(err)
	}

	switch *action {
	case "encrypt":
		{
			encrypted, err := Encrypt(data, []byte(*key))
			if err != nil {
				log.Fatal(err)
			}

			encoded := base64.URLEncoding.EncodeToString(encrypted)

			if *output != "" {
				file, err := os.Create(*output)
				if err != nil {
					log.Fatal(err)
				}

				file.Write([]byte(encoded))
				break
			}

			log.Println(encoded)

		}
	case "decrypt":
		{
			decoded, err := base64.URLEncoding.DecodeString(string(data))
			if err != nil {
				log.Fatal(err)
			}

			decrypted, err := Decrypt(decoded, []byte(*key))
			if err != nil {
				log.Fatal(err)
			}

			if *output != "" {
				file, err := os.Create(*output)
				if err != nil {
					log.Fatal(err)
				}

				file.Write(decrypted)
				break
			}

			log.Println(string(decrypted))
		}
	default:
		{
			log.Fatal("unknown action, encrypt or decrypt only")
		}
	}
}
