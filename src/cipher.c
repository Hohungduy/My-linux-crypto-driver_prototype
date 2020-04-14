/*
 * Support for Cryptographic Engine in FPGA card using PCIe interface
 * that can be found on the following platform: Armada. 
 *
 * Author: Duy H.Ho <duyhungho.work@gmail.com>
 *
 * This work is based on an initial version written by
 * Sebastian Andrzej Siewior < sebastian at breakpoint dot cc >
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <crypto/des.h>
#include <crypto/aead.h>
#include <crypto/internal/aead.h>
#include <crypto/sha.h>
#include "mycrypto.h"

struct my_crypto_cipher_op{
 void *src;
 void *dst;
 u32 dir;
 u32 flags;
 u32 mode;
 int len;
 u8 key[AES_KEYSIZE_128];
 u8 *iv;
 u32 keylen;
 
};
// Note the cra_aligmask
//struct AEAD algorithm which is registered after driver probing
static int my_crypto_aead_aes_setkey(struct crypto_aead *cipher, const u8 *key,unsigned int len)
{
	return 0;
}
static int my_crypto_aead_aes_encrypt(struct aead_request *req)
{
	printk(KERN_INFO "hello world my_crypto_aead_aes_encrypt \n");
	return 0;
}
static int my_crypto_aead_aes_decrypt(struct aead_request *req)
{
	printk(KERN_INFO "hello world my_crypto_aead_aes_decrypt \n");
	return 0;
}
static int my_crypto_aead_cra_init(struct crypto_tfm *tfm)
{
	return 0;
}
static void my_crypto_aead_cra_exit(struct crypto_tfm *tfm)
{
	
}
struct mycrypto_alg_template mycrypto_alg_gcm_aes = {
    .type = MYCRYPTO_ALG_TYPE_AEAD,
	.alg.aead = {
			.setkey = my_crypto_aead_aes_setkey,
    		.encrypt = my_crypto_aead_aes_encrypt,
    		.decrypt = my_crypto_aead_aes_decrypt,
    		.ivsize = 12,
			.maxauthsize = SHA256_DIGEST_SIZE,
    		.base = {
        			.cra_name = "authenc(hmac(sha256),ctr(aes))",
					.cra_driver_name = "mycrypto_gcm_aes",
					.cra_priority = 250,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = 1,
					.cra_ctxsize = sizeof(struct my_crypto_cipher_op),
					.cra_alignmask = 0,
					.cra_init = my_crypto_aead_cra_init,
					.cra_exit = my_crypto_aead_cra_exit,
					.cra_module = THIS_MODULE,
    		},
	},
};

struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_cbc_aes = {
    .type = MYCRYPTO_ALG_TYPE_AEAD,
	.alg.aead = {
			.setkey = my_crypto_aead_aes_setkey,
    		.encrypt = my_crypto_aead_aes_encrypt,
    		.decrypt = my_crypto_aead_aes_decrypt,
    		.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
    		.base = {
        			.cra_name = "authenc(hmac(sha256),ctr(aes))",
					.cra_driver_name = "mycrypto_gcm_aes",
					.cra_priority = 300,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = AES_BLOCK_SIZE,
					.cra_ctxsize = sizeof(struct my_crypto_cipher_op),
					.cra_alignmask = 0,
					.cra_init = my_crypto_aead_cra_init,
					.cra_exit = my_crypto_aead_cra_exit,
					.cra_module = THIS_MODULE,
    		},
	},
};


