#include "aes.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

FILE *open_file(const char *file) {
	FILE *f = fopen(file, "rb");
	if(!f) {
		printf("Unable to open file: %s\n", file);
		perror("Cause");
		exit(2);
	}
	return f;
}

uint64_t get_file_size(FILE *file, const char *name) {
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	if(size == -1) {
		printf("Error getting size of file: %s\n", name);
		perror("Cause");
		exit(3);
	}
	if(size == 0) {
		printf("File is empty: %s\n\n", name);
		exit(20);
	}
	fseek(file, 0, SEEK_SET);
	return (uint64_t)size;
}

uint8_t *read_file(FILE *file, uint64_t len, uint64_t src_size, const char *name) {
	uint64_t alloc_size = len > src_size ? len : src_size;

	// file + padding block + CBCMAC + AES key + encrypt count + file size
	char *data = calloc(1, alloc_size + 16 + 16 + 32 + 8 + 8);
	if(!data) {
		printf("Unable to allocate memory for file: %s\n\n", name);
		exit(5);
	}
	if(fread(data, len, 1, file) != 1) {
		printf("Failed to read file: %s\n", name);
		perror("Cause");
		exit(6);
	}
	return (uint8_t*)data;
}
	
void set_iv(struct AES_ctx *master_ctx, struct AES_ctx *ctx, uint64_t encrypt_count, uint8_t *iv) {
	memcpy(iv, &encrypt_count, sizeof encrypt_count);
	memset(iv, 0, 16);
	AES_ECB_encrypt(master_ctx, iv);
	AES_ctx_set_iv(ctx, iv);
}

struct state {
	struct AES_ctx *master_ctx;
  	struct AES_ctx *ctx;
  	uint8_t *src_file;
  	uint8_t *keystream;
  	uint8_t *iv;
	uint8_t *key_file;
  	uint64_t key_size;
  	uint64_t key_pos;
  	uint64_t src_size_w_mac;
  	uint64_t encrypt_count;
  	int encrypt;
};

void encrypt(struct state *s) {
	s->key_pos = 0;
	while(s->key_pos < s->key_size) {
		uint64_t count = s->key_size - s->key_pos > s->src_size_w_mac ? s->src_size_w_mac : s->key_size - s->key_pos;

		for(uint64_t i = 0; i < count; ++i)
			s->src_file[i] ^= s->keystream[s->key_pos + i];
		
		set_iv(s->master_ctx, s->ctx, s->encrypt_count++, s->iv);
		AES_PCBC_encrypt_buffer(s->ctx, s->src_file, count);
		s->key_pos += count;
	}

	if(s->key_pos != s->key_size) {
		printf("key_pos %ld is not key_size %ld\n\n", (long)s->key_pos, (long)s->key_size);
		exit(11);
	}
}

void decrypt(struct state *s) {
	s->key_pos = (s->key_size - 1) / s->src_size_w_mac * s->src_size_w_mac;
	//printf("key_size: %ld\n", (long)s->key_size);
	//printf("key_pos: %ld\n", (long)s->key_pos);
	//printf("src_size_w_mac: %ld\n", (long)s->src_size_w_mac);
	while(1) {
		if(s->encrypt_count <= 4) {
			printf("Wrong key file, input file is corrupted, or input file was not encrypted with this utility\n\n");
			exit(9);
		}
	
		uint64_t count = s->key_size - s->key_pos > s->src_size_w_mac ? s->src_size_w_mac : s->key_size - s->key_pos;
		set_iv(s->master_ctx, s->ctx, --s->encrypt_count, s->iv);
		AES_PCBC_decrypt_buffer(s->ctx, s->src_file, count);
		
		for(uint64_t i = 0; i < count; ++i)
			s->src_file[i] ^= s->keystream[s->key_pos + i];
		
		if(s->key_pos == 0)
			break;

		if(s->key_pos < s->src_size_w_mac) {	// should never happen
			printf("key_pos %ld is less than src_size_w_mac %ld\n\n", (long)s->key_pos, (long)s->src_size_w_mac);
			exit(10);
		}

		s->key_pos -= s->src_size_w_mac;
	}
}

void crypt(struct state *s) {
	if(s->encrypt)
		encrypt(s);
	else
		decrypt(s);
}

void make_keystream(struct state *s, uint64_t iv_counter) {
	memcpy(s->keystream, s->key_file, s->key_size);
	set_iv(s->master_ctx, s->ctx, iv_counter, s->iv);
	AES_PCBC_encrypt_buffer(s->ctx, s->keystream, s->key_size);
}

void reverse_bytes(uint8_t *bytes, uint64_t len) {
	for(uint64_t i = 0; i < len / 2; ++i) {
		uint8_t c = bytes[i];
		bytes[i] = bytes[len - i - 1];
		bytes[len - i - 1] = c;
	}
}

void shuffle(struct state *s) {
	make_keystream(s, 2);
	reverse_bytes(s->keystream, s->key_size);
	set_iv(s->master_ctx, s->ctx, 3, s->iv);
	AES_PCBC_encrypt_buffer(s->ctx, s->keystream, s->key_size);

	if(s->key_size % 8 || s->src_size_w_mac % 8) {	// should never happen
		printf("key_size %ld or src_size_w_mac %ld not multiple of 8\n\n", (long)s->key_size, (long)s->src_size_w_mac);
		exit(16);
	}

	for(uint64_t i = 0; i < s->key_size; i += 8) {
		uint64_t index = s->encrypt ? i : s->key_size - i - 8;
		uint64_t srcIndex1 = index % s->src_size_w_mac;
		uint64_t srcIndex2 = *(uint64_t*)(s->keystream + index) % s->src_size_w_mac / 8 * 8;
		uint8_t tmp[8];
		if(srcIndex1 != srcIndex2) {
			memcpy(tmp, s->src_file + srcIndex1, 8);
			memcpy(s->src_file + srcIndex1, s->src_file + srcIndex2, 8);
			memcpy(s->src_file + srcIndex2, tmp, 8);
		}
	}
}

int main(int argc, char **argv) {
	uint8_t master_key[32];
	uint8_t cbc_key[32] = {254, 254, 254, 254, 254, 254, 254, 254,
		254, 254, 254, 254, 254, 254, 254, 254,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255};
	uint8_t iv[16] = {0};
	uint8_t all_zero[16] = {0};

	printf("\n");

	if(argc != 5) {
		printf("Usage: %s e|d key src dest\n\n", (argc ? argv[0] : ""));
		printf("\te\tEncrypt file `src` to file `dest` using key file `key`\n");
		printf("\td\tDecrypt file `src` to file `dest` using key file `key`\n\n");
		return 1;
	}

	char action = argv[1][0];

	if(strlen(argv[1]) > 1 || (action != 'e' && action != 'E' && action != 'd' && action != 'D')) {
		printf("Unknown option `%s`, expected e or d\n\n", argv[1]);
		return 1;
	}

	int encrypt = action == 'e' || action == 'E';

	FILE *key_handle = open_file(argv[2]);
	FILE *src_handle = open_file(argv[3]);

	uint64_t key_file_size = get_file_size(key_handle, argv[2]);
	uint64_t src_file_size = get_file_size(src_handle, argv[3]);

	uint8_t *key_file = read_file(key_handle, key_file_size, src_file_size, argv[2]);
	uint8_t *src_file = read_file(src_handle, src_file_size, src_file_size, argv[3]);
	fclose(key_handle);
	fclose(src_handle);
	
	FILE *dest_handle = fopen(argv[4], "wb");
	if(!dest_handle) {
		printf("Unable to open dest file: %s\n", argv[4]);
		perror("Cause");
		return 13;
	}

	uint64_t key_size = key_file_size;
	uint64_t src_size = src_file_size;	// for encrypt
	uint64_t encrypt_count = 4;

	if(encrypt) {
		FILE *rand = fopen("/dev/urandom", "rb");
		if(!rand || fread(master_key, sizeof master_key, 1, rand) != 1) {
			printf("Unable to get randomness\n\n");
			perror("Cause");
			return 7;
		}
	} else {
		// offset from end of file:
		// -8 : file size
		// -16: encrypt count
		// -48: master AES key
		// -64: CBC-MAC
		// -80: padding block
		if(src_file_size <= 64) {
			printf("File was not encrypted with this utility. Encrypted src file is too small: %s\n\n", argv[3]);
			return 8;
		}

		src_size = *(uint64_t*)(src_file + src_file_size - 8);
		if(src_file_size != src_size / 16 * 16 + 80) {
			printf("Invalid encrypted src file: %s\n\n", argv[3]);
			return 9;
		}

		encrypt_count = *(uint64_t*)(src_file + src_file_size - 16);
		memcpy(master_key, src_file + src_file_size - 48, sizeof master_key);

		//printf("src_size: %ld\n", (long)src_size);
		//printf("encrypt_count: %ld\n", (long)encrypt_count);
	}

	uint64_t src_size_w_mac = src_size / 16 * 16 + 32;

	struct AES_ctx master_ctx;
	AES_init_ctx_iv(&master_ctx, master_key, iv);
	AES_CTR_xcrypt_buffer(&master_ctx, cbc_key, sizeof cbc_key);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, cbc_key);

	while(key_size < src_size_w_mac) {
		uint64_t copy_count = src_size_w_mac - key_size > key_file_size ? key_file_size : src_size_w_mac - key_size;
		memcpy(key_file + key_size, key_file, copy_count);
		key_size += copy_count;
	}

	key_size = (key_size - 1) / 16 * 16 + 16;

	uint8_t *keystream = malloc(key_size);
	if(!keystream) {
		printf("Failed to allocate keystream\n\n");
		return 15;
	}

	struct state s = {
		&master_ctx, &ctx, src_file, keystream, iv, key_file, key_size, 0, src_size_w_mac, encrypt_count, encrypt
	};

	if(!encrypt) {
		shuffle(&s);
	}

	make_keystream(&s, 0);
	crypt(&s);

	reverse_bytes(src_file, src_size_w_mac);
	
	make_keystream(&s, 1);
	crypt(&s);

	if(encrypt) {
		shuffle(&s);
		memcpy(src_file + src_size_w_mac, master_key, 32);
		memcpy(src_file + src_size_w_mac + 32, &s.encrypt_count, 8); 
		memcpy(src_file + src_size_w_mac + 40, &src_size, 8);
	} else {
		if(memcmp(all_zero, src_file + src_file_size - 64, 16) != 0) {
			printf("Failed to decrypt: checksum was incorrect. Wrong key file, the input file is corrupted, or input file was not created with this utility\n\n");
			return 12;
		}
	}
	if(fwrite(src_file, encrypt ? src_size_w_mac + 48 : src_size, 1, dest_handle) != 1) {
		printf("Failed to write to dest file: %s\n", argv[4]);
		perror("Cause");
		return 14;
	}

	fclose(dest_handle);
	free(src_file);
	free(key_file);
	free(keystream);
}

