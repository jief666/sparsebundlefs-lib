// _FILE_OFFSET_BITS 64 is needed for large file. Don't know if it's enough to put it here or if it must be defined globally
#define _FILE_OFFSET_BITS 64

// Comment next line if you want debug message on syslog
#define syslog(Level, ...)  do { printf(__VA_ARGS__); printf("\n"); } while (0)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // looks like I need that to get asprintf... sometimes.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h> // for getpass
#include <sys/param.h> // for MAXPATHLEN
#include <fcntl.h> // open, read, close...
#include <inttypes.h> // for PRIx64...
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifndef syslog
#include <syslog.h>
#endif
#include <sys/stat.h>


#ifdef __APPLE__
	#include <libkern/OSByteOrder.h>
	#define htobe32(x) OSSwapHostToBigInt32(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
#else
	#include <endian.h>
#endif
#include <arpa/inet.h> // for htonl

#include <libxml/xpath.h>

#include "sparsebundlefs.h"

//assert(sizeof(off_t) >= sizeof(int8_t) && sizeof(off_t) <= sizeof(intmax_t));
//const off_t OFF_T_MIN = sizeof(off_t) == sizeof(int8_t)   ? INT8_MIN    :
//						sizeof(off_t) == sizeof(int16_t)  ? INT16_MIN   :
//						sizeof(off_t) == sizeof(int32_t)  ? INT32_MIN   :
//						sizeof(off_t) == sizeof(int64_t)  ? INT64_MIN   :
//						sizeof(off_t) == sizeof(intmax_t) ? INTMAX_MIN  : 0;

//assert(sizeof(off_t) >= sizeof(int8_t) && sizeof(off_t) <= sizeof(intmax_t));
const off_t OFF_T_MAX = sizeof(off_t) == sizeof(int8_t)   ? INT8_MAX    :
						sizeof(off_t) == sizeof(int16_t)  ? INT16_MAX   :
						sizeof(off_t) == sizeof(int32_t)  ? INT32_MAX   :
						sizeof(off_t) == sizeof(int64_t)  ? INT64_MAX   :
						sizeof(off_t) == sizeof(intmax_t) ? INTMAX_MAX  : 0;

// Define
//  SPARSEBUNDLEFS_NO_CRYPTO to not use encrypted sparsebundle
//  SPARSEBUNDLEFS_USE_OPENSSL to use openssl for crypto. In that case, only sparsebundle.c needs to be compiled (+fuse if you want it).
//  SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO to use crypto from crypto source folder.

//------------------------------------------- Crypto choice
// I tried tiny-AES-C from https://github.com/kokke/tiny-AES-c.git but it was very slow.

#ifndef SPARSEBUNDLEFS_NO_CRYPTO
#  if !defined(SPARSEBUNDLEFS_USE_OPENSSL) && !defined(SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO)
#    define SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO // default : use embedded crypto
#  endif
#  define CRYPTO_AVAILABLE
#endif

#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
#  ifdef SPARSEBUNDLEFS_USE_OPENSSL
#    define COMPARE_OPENSSL_AND_EMBEDDED_CRYPTO
#  endif
#endif

//------------------------------------------- Crypto include + defines
#ifdef SPARSEBUNDLEFS_USE_OPENSSL
#  include <arpa/inet.h>
#  include "openssl/sha.h"
#  include "openssl/aes.h"
#  include "openssl/hmac.h"
#  include "openssl/evp.h"
#endif

#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO

#  include "../crypto/hmac-sha1/hmac/hmac.h"
#  include "../crypto/PBKDF2_HMAC_SHA1.h"
#  include "../crypto/Des.h"
#  include "../crypto/TripleDes.h"
#  include "../crypto/aes-rijndael/rijndael-aes.h"
#endif

#ifdef CRYPTO_AVAILABLE

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
//
#define HMACSHA1_KEY_SIZE 20 // from v2 header

#endif

//------------------------------------------- sparsebundle_data_st

struct sparsebundle_data_st;
typedef int (*read_band_func_type)(struct sparsebundle_data_st* sparsebundle_data, uint8_t* buff, size_t nbytes, off_t offset);


typedef struct sparsebundle_data_st
{
    char *path;
    off_t band_size;
    size_t blocksize;
    off_t size;
    int opened_file_band_number;
    int opened_file_fd;
	read_band_func_type read_band_func;

#ifdef CRYPTO_AVAILABLE
    uint8_t hmacsha1_key[HMACSHA1_KEY_SIZE];
    uint8_t aes_key[32]; // up to aes 256 bits
    uint8_t aes_key_size;
#endif
#ifdef SPARSEBUNDLEFS_USE_OPENSSL
//    HMAC_CTX hmacsha1_ctx;
    AES_KEY aes_decrypt_key;
#endif
#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
	aes_decrypt_ctx rijndael_ctx;
#endif
} sparsebundle_data_t;
//-------------------------------------------

int sparsebundlefs_getdatasize()
{
	return sizeof(sparsebundle_data_t);
}

/********************************************************************** Header V2 **********************************************************/

typedef struct __attribute__((packed)) {
  char sig[8];
  uint32_t version;
  uint32_t enc_iv_size;
  uint32_t encMode;
  uint32_t encAlg;
  uint32_t keyBits;
  uint32_t prngalg;
  uint32_t prngkeysize;
  unsigned char uuid[16];
  uint32_t blocksize;
  uint64_t datasize;
  uint64_t dataoffset;
  uint32_t keycount;
} cencrypted_v2_header;

typedef struct __attribute__((packed)) {
    uint32_t header_type;
    uint32_t unk1;
    uint32_t header_offset;
    uint32_t unk2;
    uint32_t header_size;
} cencrypted_v2_key_header_pointer;

typedef struct __attribute__((packed)) {
  uint32_t kdf_algorithm;
  uint32_t kdf_prng_algorithm;
  uint32_t kdf_iteration_count;
  uint32_t kdf_salt_len; /* in bytes */
  uint8_t  kdf_salt[32];
  uint32_t blob_enc_iv_size;
  uint8_t  blob_enc_iv[32];
  uint32_t blob_enc_key_bits;
  uint32_t blob_enc_algorithm;
  uint32_t blob_enc_padding;
  uint32_t blob_enc_mode;
  uint32_t encrypted_keyblob_size;
  uint8_t*  encrypted_keyblob;
} cencrypted_v2_password_header;


#ifdef DEBUG

static void print_hex(void *data, uint32_t len, const char* format, ...)
{
	uint32_t ctr;

	if (len > 512) {
		len = 512;
	}

	char buf[len*2+1];
	memset(buf, 0, sizeof(buf));
	for(ctr = 0; ctr < len; ctr++) {
		sprintf(buf + (ctr*2), "%02x", ((uint8_t *)data)[ctr]);
	}
	{
		char message[2000];
		va_list args;
		va_start(args, format);
		vsnprintf(message, sizeof(message), format, args);
		va_end(args);
		syslog(LOG_DEBUG, "%s : %s", message, buf);
	}
}

void dump_v2_header(cencrypted_v2_header *v2header)
{
	syslog(LOG_DEBUG, "V2 HEADER :");
	syslog(LOG_DEBUG, "sig %s", v2header->sig);
	syslog(LOG_DEBUG, "blocksize %u", v2header->blocksize);
	syslog(LOG_DEBUG, "datasize %llu", v2header->datasize);
	syslog(LOG_DEBUG, "dataoffset %llu", v2header->dataoffset);
	syslog(LOG_DEBUG, "keycount %u", v2header->keycount);
}

void dump_v2_key_header(cencrypted_v2_key_header_pointer *v2header)
{
	syslog(LOG_DEBUG, "V2 KEY HEADER :");
	syslog(LOG_DEBUG, "header_type %d", v2header->header_type);
	syslog(LOG_DEBUG, "header_offset %d", v2header->header_offset);
	syslog(LOG_DEBUG, "header_size %d", v2header->header_size);
}

void dump_v2_password_header(cencrypted_v2_password_header *pwhdr)
{
	syslog(LOG_DEBUG, "V2 PASSWORD HEADER :");
	/* 103: CSSM_ALGID_PKCS5_PBKDF2 */
	syslog(LOG_DEBUG, "keyDerivationAlgorithm      %lu", (unsigned long) pwhdr->kdf_algorithm);
	syslog(LOG_DEBUG, "keyDerivationPRNGAlgorithm  %lu", (unsigned long) pwhdr->kdf_prng_algorithm);
	/* by default the iteration count should be 1000 iterations */
	syslog(LOG_DEBUG, "keyDerivationIterationCount %lu", (unsigned long) pwhdr->kdf_iteration_count);
	syslog(LOG_DEBUG, "keyDerivationSaltSize       %lu", (unsigned long) pwhdr->kdf_salt_len);
	print_hex(pwhdr->kdf_salt, sizeof(pwhdr->kdf_salt), "keyDerivationSalt           ");
	syslog(LOG_DEBUG, "blobEncryptionIVSize        %lu", (unsigned long) pwhdr->blob_enc_iv_size);
	syslog(LOG_DEBUG, "blobEncryptionIV            ");
	//	print_hex(pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
	print_hex(pwhdr->blob_enc_iv, sizeof(pwhdr->blob_enc_iv), "blobEncryptionIV            ");
	syslog(LOG_DEBUG, "blobEncryptionKeySizeInBits %lu",  (unsigned long) pwhdr->blob_enc_key_bits);
	/*  17: CSSM_ALGID_3DES_3KEY_EDE */
	syslog(LOG_DEBUG, "blobEncryptionAlgorithm     %lu",  (unsigned long) pwhdr->blob_enc_algorithm);
	/*   7: CSSM_PADDING_PKCS7 */
	syslog(LOG_DEBUG, "blobEncryptionPadding       %lu",  (unsigned long) pwhdr->blob_enc_padding);
	/*   6: CSSM_ALGMODE_CBCPadIV8 */
	syslog(LOG_DEBUG, "blobEncryptionMode          %lu",  (unsigned long)  pwhdr->blob_enc_mode);
	syslog(LOG_DEBUG, "encryptedBlobSize           %lu",  (unsigned long)  pwhdr->encrypted_keyblob_size);
	print_hex(pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size, "encryptedBlob               ");
}
#endif
//#define swap32(x) x = OSSwapHostToBigInt32(x)
//#define swap64(x) x = ((uint64_t) ntohl(x >> 32)) | (((uint64_t) ntohl((uint32_t) (x & 0xFFFFFFFF))) << 32)

void adjust_v2_header_byteorder(cencrypted_v2_header *v2header)
{
	v2header->blocksize = be32toh(v2header->blocksize);
	v2header->datasize = be64toh(v2header->datasize);
	v2header->dataoffset = be64toh(v2header->dataoffset);
	v2header->keycount = be32toh(v2header->keycount);
}

void adjust_v2_key_header_pointer_byteorder(cencrypted_v2_key_header_pointer *key_header_pointer)
{
	key_header_pointer->header_type = htonl(key_header_pointer->header_type);
	key_header_pointer->header_offset = htonl(key_header_pointer->header_offset);
	key_header_pointer->header_size = htonl(key_header_pointer->header_size);
}

void adjust_v2_password_header_byteorder(cencrypted_v2_password_header *pwhdr)
{
	pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
	pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
	pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
	pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
	pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
	pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
	pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
	pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
	pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
	pwhdr->encrypted_keyblob_size = htonl(pwhdr->encrypted_keyblob_size);
}

int unwrap_v2_password_header(cencrypted_v2_password_header *pwhdr, uint8_t *hmacsha1_key, uint8_t *aes_key, uint8_t*aes_key_size_ptr, const char* password)
{
	/* derived key is a 3DES-EDE key */
	#ifdef SPARSEBUNDLEFS_USE_OPENSSL
		uint8_t derived_key_openssl[192/8];
		EVP_CIPHER_CTX ctx;
		int outlen, tmplen;
	#endif
	#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
		uint8_t derived_key[192/8];
	#endif


	if ( password != NULL ) {
		#ifdef SPARSEBUNDLEFS_USE_OPENSSL
			PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, sizeof(derived_key_openssl), derived_key_openssl);
		#endif
		#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
			PBKDF2_HMAC_SHA1((const uint8_t *)password, strlen(password), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, derived_key, sizeof(derived_key));
		#endif
	}else{
		char *aPassword = getpass("Password: ");
		#ifdef SPARSEBUNDLEFS_USE_OPENSSL
			PKCS5_PBKDF2_HMAC_SHA1(aPassword, strlen(aPassword), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, sizeof(derived_key_openssl), derived_key_openssl);
		#endif
		#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
			PBKDF2_HMAC_SHA1((const uint8_t *)aPassword, strlen(aPassword), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, derived_key, sizeof(derived_key));
		#endif
		memset(aPassword, 0, strlen(aPassword));
	}
	#ifdef COMPARE_OPENSSL_AND_EMBEDDED_CRYPTO
		if ( memcmp(derived_key_openssl, derived_key, sizeof(derived_key_openssl)) != 0 ) {
			syslog(LOG_DEBUG, "PKCS5_PBKDF2_HMAC_SHA1 doesn't give the same result with embedded crypto");
			return -1;
		}
	#endif

#ifdef DEBUG
#  ifdef SPARSEBUNDLEFS_USE_OPENSSL
    print_hex(derived_key_openssl, 192/8, "derived_key : ");
#  endif
#  ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
    print_hex(derived_key, 192/8, "derived_key : ");
#  endif
#endif

	if ( pwhdr->encrypted_keyblob_size == 48 ) {
		*aes_key_size_ptr = 16;
	}else if ( pwhdr->encrypted_keyblob_size == 64 ) {
		*aes_key_size_ptr = 32;
	}



#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
	uint8_t blob[pwhdr->encrypted_keyblob_size];

	TripleDesInit();
	TripleDesSetKey(derived_key);
	TripleDesSetIV(pwhdr->blob_enc_iv);

//	uint32_t blob_len = pwhdr->encrypted_keyblob_size;

	TripleDesDecryptCBC(blob, pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size);

	if (blob[pwhdr->encrypted_keyblob_size - 1] < 1 || blob[pwhdr->encrypted_keyblob_size - 1] > 8)
		return -1;

//	uint32_t blob_len -= blob[pwhdr->encrypted_keyblob_size - 1];
//
//	if (memcmp(blob + blob_len - 5, "CKIE", 4))
//		return -1;

	memcpy(aes_key, blob, *aes_key_size_ptr);
	memcpy(hmacsha1_key, blob+*aes_key_size_ptr, HMACSHA1_KEY_SIZE);

#endif
#ifdef SPARSEBUNDLEFS_USE_OPENSSL
	/* result of the decryption operation shouldn't be bigger than ciphertext */
	uint8_t TEMP1[pwhdr->encrypted_keyblob_size];
	/* uses PKCS#7 padding for symmetric key operations by default */

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key_openssl, pwhdr->blob_enc_iv);

	if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size)) {
		syslog(LOG_DEBUG, "internal error (1) during key unwrap operation!");
		return(-1);
	}
	if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen)) {
		syslog(LOG_DEBUG, "internal error (2) during key unwrap operation!");
		return(-1);
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	memcpy(aes_key, TEMP1, *aes_key_size_ptr);
	memcpy(hmacsha1_key, TEMP1+*aes_key_size_ptr, HMACSHA1_KEY_SIZE);

#endif
#ifdef COMPARE_OPENSSL_AND_EMBEDDED_CRYPTO
	if ( memcmp(TEMP1, blob, sizeof(pwhdr->encrypted_keyblob_size)) != 0 ) {
		syslog(LOG_DEBUG, "PKCS5_PBKDF2_HMAC_SHA1 doesn't give the same result with embedded crypto");
		return -1;
	}
#endif

//print_hex(aes_key, *aes_key_size_ptr, "aes_key(%d) : ", *aes_key_size_ptr*8);
//print_hex(hmacsha1_key, HMACSHA1_KEY_SIZE, "hmacsha1_key : ");

	return(0);
}

int v2_read_token(const char* path, cencrypted_v2_header *v2headerPtr, uint8_t* hmacsha1_key_ptr, uint8_t* aes_key_ptr, uint8_t*aes_key_size_ptr, const char* password )
{
	char token_filename[MAXPATHLEN];
	int fd_token;
	sprintf(token_filename, "%s/token", path);
	if ((fd_token = open(token_filename, O_RDONLY)) < 0) {
		syslog(LOG_DEBUG, "Error: unable to open %s", token_filename);
		exit(EXIT_FAILURE);
	}

//	cencrypted_v2_header& v2header = *v2headerPtr;
#define v2header (*v2headerPtr)
	cencrypted_v2_key_header_pointer v2keyheader;
	cencrypted_v2_password_header v2pwhdr;

	int password_header_found = 0;
	v2pwhdr.encrypted_keyblob = NULL;

	lseek(fd_token, 0L, SEEK_SET);
	if ( read(fd_token, &v2header, sizeof(v2header)) != sizeof(v2header) ) {
		syslog(LOG_DEBUG, "header corrupted?");
		exit(EXIT_FAILURE);
	}
	adjust_v2_header_byteorder(&v2header);
	#ifdef DEBUG
		dump_v2_header(&v2header);
	#endif
	if ( strcmp(v2header.sig, "encrcdsa") != 0 ) {
		syslog(LOG_DEBUG, "signature should be encrcdsa. Header corrupted? (sig=%s)", v2header.sig);
		exit(EXIT_FAILURE);
	}
	uint32_t i;
	for ( i = 0; i < v2header.keycount; i++) {
		// Seek to the start of the key header pointers offset by the current key which start immediately after the v2 header.
		if (lseek(fd_token, sizeof(v2header) + (sizeof(v2keyheader)*i), SEEK_SET) != (off_t)(sizeof(v2header) + (sizeof(v2keyheader)*i)) ) {
			syslog(LOG_DEBUG, "Unable to seek to header pointers in %s", token_filename);
			exit(EXIT_FAILURE);
		}

		// Read in the key header pointer
		ssize_t count = read(fd_token, &v2keyheader, sizeof(v2keyheader));
		if (count != sizeof(v2keyheader)) {
			syslog(LOG_DEBUG, "Unable to read key header from %s (sizeof(v2keyheaderptr)=%zd count=%zd)", token_filename, sizeof(v2keyheader), count);
			exit(EXIT_FAILURE);
		}

		adjust_v2_key_header_pointer_byteorder(&v2keyheader);
		#ifdef DEBUG
			dump_v2_key_header(&v2keyheader);
		#endif

		// We, currently, only care about the password key header. If it's not the password header type skip over it.
		if (v2keyheader.header_type != 1) {
			continue;
		}

		password_header_found = 1;

		// Seek to where the password key header is in the file.
		if (lseek(fd_token, v2keyheader.header_offset, SEEK_SET) != v2keyheader.header_offset ) {
			syslog(LOG_DEBUG, "Unable to seek to password header in %s", token_filename);
			exit(EXIT_FAILURE);
		}

		// Read in the password key header but avoid reading anything into the keyblob.
		count = read(fd_token, &v2pwhdr, sizeof(v2pwhdr) - sizeof(unsigned char *));
		if (count != sizeof(v2pwhdr) - sizeof(unsigned char *)) {
			syslog(LOG_DEBUG, "Unable to read password header from %s", token_filename);
			exit(EXIT_FAILURE);
		}

		adjust_v2_password_header_byteorder(&v2pwhdr);
		// Allocate the keyblob memory
		if ( v2pwhdr.encrypted_keyblob ) free(v2pwhdr.encrypted_keyblob);
		v2pwhdr.encrypted_keyblob = (uint8_t*)malloc(v2pwhdr.encrypted_keyblob_size); // TODO check malloc return

		if ( sizeof(v2keyheader.header_offset) >= sizeof(off_t)  &&  v2keyheader.header_offset > OFF_T_MAX - sizeof(v2pwhdr) - sizeof(unsigned char *) ) {
			syslog(LOG_DEBUG, "v2keyheader.header_offset is too big : %" PRId32, v2keyheader.header_offset);
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}
		// Seek to the keyblob in the header
		if (lseek(fd_token, v2keyheader.header_offset + sizeof(v2pwhdr) - sizeof(unsigned char *), SEEK_SET) != (off_t)(v2keyheader.header_offset + sizeof(v2pwhdr) - sizeof(unsigned char *)) ) // cast to off_t is safe because of check before
		{
			syslog(LOG_DEBUG, "Unable to seek to password header in %s", token_filename);
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}

		// Read in the keyblob
		count = read(fd_token, v2pwhdr.encrypted_keyblob, v2pwhdr.encrypted_keyblob_size);
		if (count != (ssize_t)v2pwhdr.encrypted_keyblob_size) {
			syslog(LOG_DEBUG, "Unable to read blob from %s (v2pwhdr.encrypted_keyblob_size=%u)", token_filename, v2pwhdr.encrypted_keyblob_size);
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}
		#ifdef DEBUG
			dump_v2_password_header(&v2pwhdr);
		#endif
		if ( unwrap_v2_password_header(&v2pwhdr, hmacsha1_key_ptr, aes_key_ptr, aes_key_size_ptr, password) == -1 ) {
			syslog(LOG_DEBUG, "Unable to unwrap. Wrong password ?");
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}


		// We only need one password header. Don't search any longer.
		break;
	}

	if (!password_header_found) {
		syslog(LOG_DEBUG, "Password header not found in %s", token_filename);
		exit(EXIT_FAILURE);
	}

	if (v2pwhdr.kdf_salt_len > 32) {
		syslog(LOG_DEBUG, "%s is not a valid DMG file, salt length is too long!", token_filename);
		free(v2pwhdr.encrypted_keyblob);
		exit(EXIT_FAILURE);
	}

syslog(LOG_DEBUG, "%s (DMG v%d) successfully parsed, iterations count %u", token_filename, 2, v2pwhdr.kdf_iteration_count);

	free(v2pwhdr.encrypted_keyblob);
	return 0;
}
#undef v2header
/********************************************************************** Sparsebundle read **********************************************************/

#ifdef CRYPTO_AVAILABLE

/**
 * Compute IV of current block as
 * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 */
void compute_iv(uint32_t chunk_no, uint8_t *iv, sparsebundle_data_t* sparsebundle_data)
{
	chunk_no = htobe32(chunk_no);

#ifdef SPARSEBUNDLEFS_USE_OPENSSL
	unsigned char mdResultOpenSsl[MD_LENGTH];
	unsigned int mdLenOpenSsl;

    HMAC_CTX hmacsha1_ctx;
	HMAC_CTX_init(&hmacsha1_ctx);
	HMAC_Init_ex(&hmacsha1_ctx, sparsebundle_data->hmacsha1_key, sizeof(sparsebundle_data->hmacsha1_key), EVP_sha1(), NULL);
	HMAC_Update(&hmacsha1_ctx, (const unsigned char *) &chunk_no, sizeof(uint32_t));
	HMAC_Final(&hmacsha1_ctx, mdResultOpenSsl, &mdLenOpenSsl);
	HMAC_CTX_cleanup(&hmacsha1_ctx);

//	HMAC_CTX_init(&sparsebundle_data->hmacsha1_ctx);
//	HMAC_Init_ex(&sparsebundle_data->hmacsha1_ctx, sparsebundle_data->hmacsha1_key, sizeof(sparsebundle_data->hmacsha1_key), EVP_sha1(), NULL);
//	HMAC_Update(&(sparsebundle_data->hmacsha1_ctx), (const unsigned char *) &chunk_no, sizeof(uint32_t));
//	HMAC_Final(&(sparsebundle_data->hmacsha1_ctx), mdResultOk, &mdLenOk);
	memcpy(iv, mdResultOpenSsl, CIPHER_BLOCKSIZE);
#endif
#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
	unsigned char mdResult2[MD_LENGTH];
	size_t mdLen2;
	mdLen2 = sizeof(mdResult2);
	hmac_sha1(sparsebundle_data->hmacsha1_key, sizeof(sparsebundle_data->hmacsha1_key), (const unsigned char *) &chunk_no, sizeof(chunk_no), mdResult2, &mdLen2);
	memcpy(iv, mdResult2, CIPHER_BLOCKSIZE);
#endif

#if defined(SPARSEBUNDLEFS_USE_OPENSSL) && defined(SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO) && defined(COMPARE_OPENSSL_AND_EMBEDDED_CRYPTO)
	if ( mdLenOpenSsl != mdLen2  ||  memcmp(mdResultOpenSsl, mdResult2, mdLenOpenSsl) != 0 ) {
		syslog(LOG_ERR, "compute_iv OpenSsl != EmbeddedSsl");
	}
#endif
}


void decrypt_chunk(void *crypted_buffer, uint32_t chunk_no, sparsebundle_data_t* sparsebundle_data)
{
	uint8_t iv[CIPHER_BLOCKSIZE];

#if defined(SPARSEBUNDLEFS_USE_OPENSSL) && defined(SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO)
	uint8_t crypted_buffer_sav[sparsebundle_data->blocksize];
	memcpy(crypted_buffer_sav, crypted_buffer, sparsebundle_data->blocksize);
#endif


#ifdef SPARSEBUNDLEFS_USE_OPENSSL
	uint8_t decrypted_buffer_openssl[sparsebundle_data->blocksize];
	compute_iv(chunk_no, iv, sparsebundle_data);
//print_hex(iv, CIPHER_BLOCKSIZE, "decrypt_chunk  chunk_no=%d, iv=", chunk_no);
//print_hex(sparsebundle_data->aes_key, sparsebundle_data->aes_key_size, "aes key=");
	AES_cbc_encrypt((uint8_t *)crypted_buffer, (uint8_t *)decrypted_buffer_openssl, sparsebundle_data->blocksize, &(sparsebundle_data->aes_decrypt_key), iv, AES_DECRYPT);
//print_hex(crypted_buffer, sparsebundle_data->blocksize, "crypted_buffer=");
	memcpy(crypted_buffer, decrypted_buffer_openssl, sparsebundle_data->blocksize);
//print_hex(decrypted_buffer_openssl, sparsebundle_data->blocksize, "decrypted_buffer_openssl=");
#endif

#if defined(SPARSEBUNDLEFS_USE_OPENSSL) && defined(SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO)
	memcpy(crypted_buffer, crypted_buffer_sav, sparsebundle_data->blocksize);
#endif

#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
		uint8_t rijndael_decrypted_buffer[sparsebundle_data->blocksize];
		compute_iv(chunk_no, iv, sparsebundle_data);
    	aes_cbc_decrypt((uint8_t*)crypted_buffer, rijndael_decrypted_buffer, sparsebundle_data->blocksize, iv, &sparsebundle_data->rijndael_ctx);
    	memcpy(crypted_buffer, rijndael_decrypted_buffer, sparsebundle_data->blocksize);
#endif

#if defined(COMPARE_OPENSSL_AND_EMBEDDED_CRYPTO)
	if ( memcmp(decrypted_buffer_openssl, rijndael_decrypted_buffer, sparsebundle_data->blocksize) != 0 ) {
		syslog(LOG_ERR, "decrypt_chunk OpenSsl != rijndael");
	}
#endif
}
#endif

//int cache_hit = 0;
int cache2_hit = 0;
int last_band_number = -1;
int last_band_offset = -1;

int sparsebundle_iterate_bands(sparsebundle_data_t* sparsebundle_data, uint8_t* buffer, size_t nbytes, off_t offset)
{
//syslog(LOG_DEBUG, "ENTER - sparsebundle_iterate_bands nbytes=%zu - offset %" PRId64, nbytes, offset);
    if (offset >= sparsebundle_data->size)
        return 0;
    if (nbytes >= OFF_T_MAX)
        return 0;

    if ( offset + (off_t)nbytes > sparsebundle_data->size) {
        nbytes = sparsebundle_data->size - offset;
    }

//syslog(LOG_DEBUG, "iterating %zu bytes at offset %" PRId64, nbytes, offset);

    size_t bytes_read = 0;
    while (bytes_read < nbytes) {
        off_t band_number = (offset + bytes_read) / sparsebundle_data->band_size;
        off_t band_offset = (offset + bytes_read) % sparsebundle_data->band_size;

        ssize_t to_read = nbytes - bytes_read;
        if ( to_read > sparsebundle_data->band_size - band_offset )  to_read = sparsebundle_data->band_size - band_offset;

        // Caching opened file desciptor to avoid open and close.
        if ( sparsebundle_data->opened_file_band_number != band_number )
        {
        	if ( sparsebundle_data->opened_file_fd != -1 ) close(sparsebundle_data->opened_file_fd);
			char band_path[MAXPATHLEN+1];
			snprintf(band_path, MAXPATHLEN, "%s/bands/%" PRIx64, sparsebundle_data->path, (uint64_t)band_number);
        	sparsebundle_data->opened_file_fd = open(band_path, O_RDONLY);
        	if ( sparsebundle_data->opened_file_fd == -1 ) {
        		sparsebundle_data->opened_file_band_number = -1;
        		return -1;
        	}
        	sparsebundle_data->opened_file_band_number = band_number;
        }else{
        	//to get an idea if this cache is useful, uncomment the following
        	//cache_hit++;
        	//if ( cache_hit % 1000 == 0 ) printf("cache hit %d times\n", cache_hit);
        }

if ( last_band_number == band_number && last_band_offset == band_offset ) {
	cache2_hit++;
	printf("cache2 would hit %d times\n", cache2_hit);
}
last_band_number = band_number;
last_band_offset = band_offset;

//syslog(LOG_DEBUG, "processing %zu/%zu bytes from band %" PRId64" at offset %" PRId64, to_read, bytes_read, band_number, band_offset);

        ssize_t read = sparsebundle_data->read_band_func(sparsebundle_data, buffer+bytes_read, to_read, band_offset);
        if (read < 0) {
            return -1;
        }

        if (read < to_read) {
            ssize_t to_pad = to_read - read;
//syslog(LOG_DEBUG, "missing %zd bytes from band %" PRId64", padding with zeroes (bytes_read=%zd, to_read=%zd, read=%zd)", to_pad, band_number, bytes_read, to_read, read);
            if ( to_pad+bytes_read+read > nbytes ) {
            	exit(1);
            }
            memset(buffer+bytes_read+read, 0, to_pad);
            read += to_pad;
        }

        bytes_read += read;

//syslog(LOG_DEBUG, "done processing band %" PRId64", %zd bytes left to read", band_number, nbytes - bytes_read);
    }

    assert(bytes_read == nbytes);
    return bytes_read;
}

static int sparsebundle_read_process_band_not_encrypted(sparsebundle_data_t* sparsebundle_data, uint8_t* buff, size_t nbytes, off_t band_offset)
{
//syslog(LOG_DEBUG, "reading %zu bytes at offset %" PRId64" into %p", nbytes, offset, buff);
	ssize_t read = pread(sparsebundle_data->opened_file_fd, buff, nbytes, band_offset);
	return read;
}

#ifdef CRYPTO_AVAILABLE
static int sparsebundle_read_process_band_encrypted(sparsebundle_data_t* sparsebundle_data, uint8_t* buff, size_t nbytes, off_t band_offset)
{
//syslog(LOG_DEBUG, "ENTER - sparsebundle_read_process_band_encrypted band_path=%s - nbytes=%zu - offset %'" PRId64, band_path, nbytes, band_offset);
    off_t block_number = band_offset/512;
//syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted block number  %" PRId64, block_number);
    off_t block_offset = block_number * 512;
//syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted block_offset  %" PRId64, block_offset);
    off_t delta_offset = band_offset - block_offset;
//syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted delta_offset  %" PRId64, delta_offset);
    char inbuf[sparsebundle_data->blocksize];

//if ( delta_offset != 0 ) {
//syslog(LOG_DEBUG, "delta_offset=%" PRId64"", delta_offset);
//}
    ssize_t readtotal = 0;

//syslog(LOG_DEBUG, "reading %zu bytes at offset %" PRId64" into %p", nbytes, offset, buff);

    	while (nbytes > 0)
    	{
    		size_t to_copy = sparsebundle_data->blocksize - delta_offset;
    		if ( nbytes < to_copy ) to_copy = nbytes; // cannot use min, it gives an error.
//syslog(LOG_DEBUG, "delta_offset == %lld reading %zu bytes at offset %lld into %p", delta_offset, sparsebundle_data->blocksize, block_offset, buff);
    		if ( to_copy != sparsebundle_data->blocksize ) {
//syslog(LOG_DEBUG, "reading %zu bytes at offset %" PRId64" into %p (block_number=%" PRId64", block_offset=%" PRId64", delta_offset=%" PRId64")", to_copy, block_offset, buff, block_number, block_offset, delta_offset);
				ssize_t nbread = pread(sparsebundle_data->opened_file_fd, inbuf, sparsebundle_data->blocksize, block_offset); // returns 0 at end of file
                if (nbread != (ssize_t)sparsebundle_data->blocksize ) {
                    if ( nbread == -1 ) {syslog(LOG_ERR, "Error(1) band %s/bands/%" PRIx64 ", offset %" PRId64", nbytes %zd, errno=%d (%s) -> will be pad with 0", sparsebundle_data->path, (uint64_t)sparsebundle_data->opened_file_band_number, block_offset, sparsebundle_data->blocksize, errno, strerror(errno));}
                    else syslog(LOG_ERR, "End(1) of band %s/bands/%" PRIx64 ", offset %" PRId64", nbytes %zd, nb read=%zd -> will be pad with 0", sparsebundle_data->path, (uint64_t)sparsebundle_data->opened_file_band_number, block_offset, sparsebundle_data->blocksize, nbread);
                    if ( nbread < 0 ) {
//syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - nbytes=%zu - offset %" PRId64" -- returns %zu", band_path, nbytes, offset, nbread);
                    	return nbread;
                    }
//syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - nbytes=%zu - offset %" PRId64" -- returns %zu", band_path, nbytes, offset, readtotal);
                    return readtotal;
                }
            	decrypt_chunk(inbuf, block_number, sparsebundle_data);
            	memcpy(buff, inbuf+delta_offset, to_copy);
    		}else{
    			ssize_t nbread = pread(sparsebundle_data->opened_file_fd, buff, sparsebundle_data->blocksize, block_offset); // returns 0 at end of file
                if (nbread != (ssize_t)sparsebundle_data->blocksize ) {
                    if ( nbread == -1 ) syslog(LOG_ERR, "Error(2) band %s/bands/%" PRIx64 ", offset %" PRId64", nbytes %zd, errno=%d (%s) -> will be pad with 0", sparsebundle_data->path, (uint64_t)sparsebundle_data->opened_file_band_number, block_offset, sparsebundle_data->blocksize, errno, strerror(errno));
                    else syslog(LOG_ERR, "End(2) of band %s/bands/%" PRIx64 ", offset %" PRId64", nbytes %zd, nb read=%zd -> will be pad with 0", sparsebundle_data->path, (uint64_t)sparsebundle_data->opened_file_band_number, block_offset, sparsebundle_data->blocksize, nbread);
                    if ( nbread < 0 ) {
//syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - nbytes=%zu - offset %" PRId64" -- returns %zu", band_path, nbytes, offset, nbread);
                    	return nbread;
                    }
//syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - nbytes=%zu - offset %" PRId64" -- returns %zu", band_path, nbytes, offset, readtotal);
                    return readtotal;
                }
//syslog(LOG_DEBUG, "12 sparsebundle_data->blocksize=%lu", sparsebundle_data->blocksize);
//print_hex(inbuf, 32, "block %" PRId64" - offsset %" PRId64" %" PRIx64" crypted : ", block_offset/sparsebundle_data->blocksize, block_offset, block_offset);
            	decrypt_chunk(buff, block_number, sparsebundle_data);
//print_hex(buff, 32, "block %" PRId64" - offsset %" PRId64" %" PRIx64" decrypt : ", block_offset/sparsebundle_data->blocksize, block_offset, block_offset);
    		}
        	buff += to_copy;
        	readtotal += to_copy;
        	nbytes -= to_copy;
        	block_offset += sparsebundle_data->blocksize;
        	block_number += 1;
        	delta_offset = 0;
    	}
        return readtotal;
}
#endif

size_t sparsebundlefs_read(void* sparsebundle_data, uint8_t *buffer, size_t nbytes, off_t offset)
{
//syslog(LOG_DEBUG, "ENTER - sparsebundle_read  offset=%llu  nbytes=%zd", offset, nbytes);
		return sparsebundle_iterate_bands((sparsebundle_data_t*)sparsebundle_data, buffer, nbytes, offset);
}

int sparsebundlefs_close(void* sparsebundle_data)
{
//syslog(LOG_DEBUG, "sparsebundle_close");
	free(((sparsebundle_data_t*)sparsebundle_data)->path);
  	if ( ((sparsebundle_data_t*)sparsebundle_data)->opened_file_fd != -1 ) close(((sparsebundle_data_t*)sparsebundle_data)->opened_file_fd);
    return 0;
}

uint64_t xpath_get_integer(const char* filename, const xmlChar* xpathExpr) {
    xmlDocPtr doc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;

    assert(filename);
    assert(xpathExpr);

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
		fprintf(stderr, "Error: unable to parse file \"%s\"\n", filename);
		return(-1);
    }
//xmlDocDump(stdout, doc);

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if(xpathObj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(UINT64_MAX);
    }
    if ( xpathObj->nodesetval->nodeNr == 0 ) {
        fprintf(stderr,"Error: no node are returned by xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(UINT64_MAX);
    }
    if ( xpathObj->nodesetval->nodeNr > 1 ) {
        fprintf(stderr,"Error: too much node (%d) are returned by xpath expression \"%s\"\n", xpathObj->nodesetval->nodeNr, xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(UINT64_MAX);
    }

    char* rv_as_string = (char*)xmlNodeGetContent(xpathObj->nodesetval->nodeTab[0]);
    if ( !rv_as_string ) {
        fprintf(stderr,"Error: no content returned by xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(UINT64_MAX);
    }

    uint64_t rv = strtoumax(rv_as_string, 0, 10);

    /* Cleanup */
    free(rv_as_string);
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    return(rv);
}

int sparsebundlefs_open(const char* path, const char* password, void* sparsebundle_data_void)
{
    if (!path) {
    	errno = ENOENT;
        return -1;
    }

    sparsebundle_data_t* sparsebundle_data = (sparsebundle_data_t*)sparsebundle_data_void;
    bzero(sparsebundle_data, sizeof(*sparsebundle_data));
    sparsebundle_data->path = realpath(path, NULL);
    if (!sparsebundle_data->path) {
    	errno = ENOENT;
        return -1;
    }

    sparsebundle_data->blocksize = 512;
    sparsebundle_data->band_size = 0;
    sparsebundle_data->read_band_func = sparsebundle_read_process_band_not_encrypted;
    sparsebundle_data->opened_file_fd = -1;
    sparsebundle_data->opened_file_band_number = -1;


    {
      struct stat st;
      cencrypted_v2_header v2header;
      char* token_filename;
    	if ( asprintf(&token_filename, "%s/token", sparsebundle_data->path) < strlen("token") ) {
  			syslog(LOG_ERR, "Failed to asprintf token path '%s/token'. %s (errno %d)", sparsebundle_data->path, strerror(errno), errno);
        	return EXIT_FAILURE;
    	}
    	if ( stat(token_filename, &st) != 0 ) {
  			syslog(LOG_ERR, "Failed to stat token file '%s'. %s (errno %d)", token_filename, strerror(errno), errno);
    		free(token_filename);
        	return EXIT_FAILURE;
    	}
    	free(token_filename);
    	if (st.st_size > (off_t)(sizeof(cencrypted_v2_header)))
    	{
			#ifndef CRYPTO_AVAILABLE
    			syslog(LOG_ERR, "Sparsebundlefs was built without crypto and this sparsebundle seems to be encrypted (token file size > %zd)", sizeof(cencrypted_v2_header));
    			return EXIT_FAILURE;
    		#endif
    		v2_read_token(sparsebundle_data->path, &v2header, sparsebundle_data->hmacsha1_key, sparsebundle_data->aes_key, &sparsebundle_data->aes_key_size, password);
    		sparsebundle_data->blocksize = v2header.blocksize;

#ifdef SPARSEBUNDLEFS_USE_OPENSSL
//    		HMAC_CTX_init(&data->hmacsha1_ctx);
//    		HMAC_Init_ex(&data->hmacsha1_ctx, data->hmacsha1_key, sizeof(data->hmacsha1_key), EVP_sha1(), NULL);
    		if ( sparsebundle_data->aes_key_size != 16  &&  sparsebundle_data->aes_key_size != 32 ) {
    			syslog(LOG_ERR, "data->aes_key_size != 16 or 32");
    			return EXIT_FAILURE;
    		}
    		AES_set_decrypt_key(sparsebundle_data->aes_key, sparsebundle_data->aes_key_size * 8, &sparsebundle_data->aes_decrypt_key);
#endif
#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
    		if ( sparsebundle_data->aes_key_size == 16 ) aes_decrypt_key128(sparsebundle_data->aes_key, &sparsebundle_data->rijndael_ctx);
    		if ( sparsebundle_data->aes_key_size == 32 ) aes_decrypt_key256(sparsebundle_data->aes_key, &sparsebundle_data->rijndael_ctx);
#endif
    		sparsebundle_data->read_band_func = sparsebundle_read_process_band_encrypted;
    	}

    }

    char *plist_path;
    if (asprintf(&plist_path, "%s/Info.plist", sparsebundle_data->path) == -1) {
		syslog(LOG_ERR, "Failed to asprintf Info.plist path '%s/Info.plist'. %s (errno %d)", plist_path, strerror(errno), errno);
        perror("Failed to resolve Info.plist path");
        return EXIT_FAILURE;
    }
	sparsebundle_data->band_size = xpath_get_integer(plist_path, (const xmlChar*)"/plist/dict/key[.='band-size']/following-sibling::integer[1]");
	if ( sparsebundle_data->band_size == 0 ) {
		free(sparsebundle_data->path);
		free(plist_path);
		return ENXIO;
	}
	sparsebundle_data->size = xpath_get_integer(plist_path, (const xmlChar*)"/plist/dict/key[.='size']/following-sibling::integer[1]");
	if ( sparsebundle_data->size == 0 ) {
		free(sparsebundle_data->path);
		free(plist_path);
		return ENXIO;
	}
    free(plist_path);

#ifdef CRYPTO_AVAILABLE
	#ifdef SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO
		if ( sparsebundle_data->read_band_func == sparsebundle_read_process_band_encrypted ) {
			syslog(LOG_DEBUG, "Initialized %s, band size %" PRId64", total size %" PRId64 " using embedded crypto", sparsebundle_data->path, sparsebundle_data->band_size, sparsebundle_data->size);
		}else{
			syslog(LOG_DEBUG, "Initialized %s, band size %" PRId64", total size %" PRId64 " not encrypted", sparsebundle_data->path, sparsebundle_data->band_size, sparsebundle_data->size);
		}
	#endif
	#ifdef SPARSEBUNDLEFS_USE_OPENSSL
		if ( sparsebundle_data->read_band_func == sparsebundle_read_process_band_encrypted ) {
			syslog(LOG_DEBUG, "Initialized %s, band size %" PRId64", total size %" PRId64 " using openssl crypto", sparsebundle_data->path, sparsebundle_data->band_size, sparsebundle_data->size);
		}else{
			syslog(LOG_DEBUG, "Initialized %s, band size %" PRId64", total size %" PRId64 " not encrypted", sparsebundle_data->path, sparsebundle_data->band_size, sparsebundle_data->size);
		}
	#endif
#else
		syslog(LOG_DEBUG, "Initialized %s, band size %" PRId64", total size %" PRId64 " not encrypted", sparsebundle_data->path, sparsebundle_data->band_size, sparsebundle_data->size);
#endif

	return 0;
}

size_t sparsebundlefs_getsize(void* sparsebundle_data)
{
	return ((sparsebundle_data_t*)sparsebundle_data)->size;
}

size_t sparsebundlefs_getblocksize(void* sparsebundle_data)
{
	return ((sparsebundle_data_t*)sparsebundle_data)->blocksize;
}

char* sparsebundlefs_getpath(void* sparsebundle_data)
{
	return ((sparsebundle_data_t*)sparsebundle_data)->path;
}
