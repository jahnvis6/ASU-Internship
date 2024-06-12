#include <openssl/err.h>
#include <stdio.h> 
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}


void print_hex(const char* label, const unsigned char* buf, int len) {
	printf("%s: ", label);
	for (int i = 0; i < len; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

void generate_random_number() {
	unsigned char buf[16];
	if (RAND_bytes(buf, sizeof(buf)) !=1) {
		handleErrors();
	}
	print_hex("Random number", buf, sizeof(buf));
}


void create_sha256_hash(const char* message) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)message, strlen(message), hash);
	print_hex("SHA-256 hash", hash, SHA256_DIGEST_LENGTH);
}

void aes_encrypt_decrypt() {
	unsigned char key[32];
	unsigned char iv[16];
	unsigned char plaintext[] = "Hello, OpenSSL!";
	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];
	int decryptedtext_len, ciphertext_len;

	// Generate random key and IV
	if (RAND_bytes(key, sizeof(key)) !=1 || RAND_bytes (iv, sizeof(iv)) !=1) {
		handleErrors();
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		handleErrors();
	}

	// Encryption
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		handleErrors();
	}

	int len;
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext))) {
		handleErrors();
	}
	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		handleErrors();
	}
	ciphertext_len +=len;

	print_hex("Ciphertext", ciphertext, ciphertext_len);


	// Decryption
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		handleErrors();
	}

	if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) {
		handleErrors();
	}
	decryptedtext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
		handleErrors();
	}
	decryptedtext_len += len;

	decryptedtext[decryptedtext_len] = '\0';

	printf("Decrypted text: %s\n", decryptedtext);

	EVP_CIPHER_CTX_free(ctx);
}


int main() {
	// Load error strings for OpenSSL
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	generate_random_number();
	create_sha256_hash("Hello, world!");
	aes_encrypt_decrypt();

	// Clean up
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
