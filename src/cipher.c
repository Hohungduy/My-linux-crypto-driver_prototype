/*
 * Support for Cryptographic Engine in FPGA card using PCIe interface
 * that can be found on the following platform: Armada. 
 *
 * Author: Duy H.Ho <duyhungho.work@gmail.com>
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
#include <crypto/authenc.h>
#include "mycrypto.h"

/* driver logic flags */
#define AES_MODE_CBC 0
#define AES_MODE_GCM 1
#define AES_MODE_AUTHENC_HMAC_CBC 2
#define AES_MODE_AUTHENC_HMAC_CTR 3

#define MYCRYPTO_DIR_DECRYPT 0
#define MYCRYPTO_DIR_ENCRYPT 1
static int mycrypto_skcipher_handle_request(struct crypto_async_request *base);
static int mycrypto_skcipher_handle_result(struct crypto_async_request *base,bool *should_complete);
/* transformation object context
* it is stored in tfm ->__crt_ctx
* and tfm = req->base.tfm 
*
*/

// base: filled in cra_init
// mydevice: filled in cra_init
// src/dst:
// dir: filled mycrypto_queue_req
// flags:
//mode: filled in mycrypto_queue_req
//len : filled in mycrypto_queue_req
// key: filled in setkey
//keylen: filled in setkey
//iv filled in mycrypto_queue_req

struct mycrypto_cipher_op{
	struct mycrypto_req_operation base;
	struct mycrypto_dev *mydevice;
	void *src;// src data -before operation
	void *dst;// dest data -after operation
	u32 dir; // direction
	u32 flags;
	u32 mode;//algoritm used
	int len;// blocksize
	u8 key[AES_KEYSIZE_128];// key
	u8 *iv; //iv pointer
	u32 keylen;//keylen
	/* all the belows is using for AEAD specific*/
	u32 hash_alg;
	u32 state_sz;
	__be32 ipad[SHA512_DIGEST_SIZE / sizeof(u32)];
	__be32 opad[SHA512_DIGEST_SIZE / sizeof(u32)];

	/* use for gcm */
	struct crypto_cipher *hkaes;// transformation object
};

/*
 *  struct mycrypto_cipher_req -- cipher request ctx 
 *  which is stored in req ->_ctx
 * @src_nents:	number of entries in the src sg list
 * @dst_nents:	number of entries in the dest sg list
*/
// dir: filled in mycrypto_queue_req
// src_nents + dst_nents: filled in mycrypto_skcipher_req_init
struct mycrypto_cipher_req{
	u32 dir; // direction ( encrypt or decrypt)
	int src_nents;
	int dst_nents;
};

static int mycrypto_skcipher_handle_request(struct crypto_async_request *base)
{
	//int ret;
	printk(KERN_INFO "module mycrypto: handle request (copy to buffer)\n");
	struct skcipher_request *req = skcipher_request_cast(base);
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(req->base.tfm);
	// context for transformation object
	struct mycrypto_cipher_req *req_ctx = skcipher_request_ctx(req);
	//context for skcipher request
	struct mycrypto_dev *mydevice = ctx->mydevice;
	size_t len = (size_t)req->cryptlen;
	//ret = mycrypto_handle_request(base,req_ctx,req->src,req->dst,req->cryptlen,0,0,req->iv);
	len = sg_pcopy_to_buffer(req->src, req_ctx->src_nents,
				 mydevice->buffer,
				 len, 0);
	// Turn on timer.
	return 0;
}
static int mycrypto_skcipher_handle_result(struct crypto_async_request *base, bool *should_complete)
{
	//int ret;
	printk(KERN_INFO "module mycrypto: handle request (copy from buffer)\n");
	struct skcipher_request *req = skcipher_request_cast(base);
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mycrypto_cipher_req *req_ctx = skcipher_request_ctx(req);
	struct mycrypto_dev *mydevice = ctx->mydevice;
	size_t len = (size_t)req->cryptlen;
	len = sg_pcopy_from_buffer(req->dst, req_ctx->dst_nents,
				 mydevice->buffer,
				 len, 0);
	*should_complete = true;
	return 0;
}
static int mycrypto_skcipher_req_init(struct skcipher_request *req)
{
	struct mycrypto_cipher_req *req_ctx = skcipher_request_ctx(req);
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	unsigned int blksize = crypto_skcipher_blocksize(tfm);
	int ret = 0;
	if (!IS_ALIGNED(req->cryptlen, blksize))
		return -EINVAL;
	req_ctx->src_nents = sg_nents_for_len(req->src, req->cryptlen);
	if (req_ctx->src_nents < 0) {
		printk(KERN_INFO "Invalid number of src SG\n");
		return req_ctx->src_nents;
	}
	req_ctx->dst_nents = sg_nents_for_len(req->dst, req->cryptlen);
	if (req_ctx->dst_nents < 0) {
		printk(KERN_INFO "Invalid number of dst SG\n");
		return req_ctx->dst_nents;
	}
	return ret;

}

static int mycrypto_queue_req(struct crypto_async_request *base,
			struct mycrypto_cipher_req *req_ctx,
			u32 dir, u32 mode)
{
	printk(KERN_INFO "module mycrypto: enqueue request\n");
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(base->tfm);
	struct skcipher_request *req = skcipher_request_cast(base);
	struct mycrypto_dev *mydevice = ctx->mydevice;
	int ret;
	req_ctx->dir = dir;
	ctx->mode = mode;
	ctx->dir =dir;
	ctx->len = AES_BLOCK_SIZE;
	ctx->iv = req->iv;
	spin_lock_bh(&mydevice->queue_lock);
	ret = crypto_enqueue_request(&mydevice->queue, base);
	spin_unlock_bh(&mydevice->queue_lock);
	// dequeue using workqueue;

	queue_work(mydevice->workqueue,
		   &mydevice->work_data.work);

	// dequeue without using workqueue (test)
	//mycrypto_dequeue_req(mydevice);
	return ret;
}

static int my_crypto_skcipher_aes_setkey(struct crypto_skcipher *cipher, const u8 *key,unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(cipher);
	// Get/retrieve transformation object
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	// Get transformation context 
	struct mycrypto_dev *mydevice = ctx->mydevice;
	struct crypto_aes_ctx aes; 
	/* @aes: The location where the processing key (computed key) will be store*/
	int ret,i;
	printk(KERN_INFO "Module mycrypto: mycrypto_skcipher_aes_setkey \n");
	ret =crypto_aes_expand_key(&aes, key,len);
	// get key and let it adapt standard criteria of aes, then store it into struct aes.
	if(ret){
		crypto_skcipher_set_flags(cipher,CRYPTO_TFM_RES_BAD_KEY_LEN);
		return ret;
	}
	// copy key stored in aes to ctx
	for(i = 0; i < len /sizeof(u32); i++)
		ctx->key[i] = cpu_to_le32(aes.key_enc[i]);
	ctx->keylen = len;
	//Beside, it is not necessary to fill aes.key_dec.
	//If you wanna continue, just refer to setkey function for skcipher 
	//in file cipher.c (mv_cesa)
	memzero_explicit(&aes, sizeof(aes));
	//free memory
	return 0;
}
static int my_crypto_cbc_aes_encrypt(struct skcipher_request *req)
{
	printk(KERN_INFO "Module mycrypto: mycrypto_skcipher_aes_encrypt \n");
	// Queue request-------
		// -------------------------------------------------------
	//check request ( src number entry / dst number entry)
	int ret;
	//struct skcipher_request *req = skcipher_request_cast(base);
	//struct mycrypto_cipher_req *req_ctx = skcipher_request_ctx(req);
	ret = mycrypto_skcipher_req_init(req);
	if (ret)
		printk(KERN_INFO "ERROR SRC/DEST NUMBER OF ENTRY\n");
	//----------------------------------------------------
	return mycrypto_queue_req(&req->base, skcipher_request_ctx(req),
			MYCRYPTO_DIR_ENCRYPT, AES_MODE_CBC);
}
static int my_crypto_cbc_aes_decrypt(struct skcipher_request *req)
{
	printk(KERN_INFO "Module mycrypto: mycrypto_skcipher_aes_decrypt \n");
	return mycrypto_queue_req(&req->base, skcipher_request_ctx(req),
			MYCRYPTO_DIR_DECRYPT, AES_MODE_CBC);
}

static int my_crypto_skcipher_cra_init(struct crypto_tfm *tfm)
{
	printk(KERN_INFO "Module mycrypto: my_crypto_skcipher_cra_init\n");
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	struct mycrypto_alg_template *tmpl =
		container_of(tfm->__crt_alg, struct mycrypto_alg_template,
			     alg.skcipher.base);
	// it means that tfm->__crt_alg
	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
				    sizeof(struct mycrypto_cipher_req));
	ctx->mydevice = tmpl->mydevice;
	ctx->base.handle_request = mycrypto_skcipher_handle_request;
	ctx->base.handle_result = mycrypto_skcipher_handle_result;

	return 0;
}
static void my_crypto_skcipher_cra_exit(struct crypto_tfm *tfm)
{
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	memzero_explicit(ctx, tfm->__crt_alg->cra_ctxsize);
}
//--------------------------------------------------------------------
static int my_crypto_aead_aes_setkey(struct crypto_aead *cipher, const u8 *key,unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(cipher);
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	//struct my_crypto_hash_state istate,ostate;
	struct mycrypto_dev *mydevice = ctx->mydevice;
	struct crypto_authenc_keys keys;
	/* @keys: The location where the processing key  
	(computed key for encrypt/decrypt and authentication) 
	will be store
	*/
	//--- Check condition of key (authenc style)
	printk(KERN_INFO "Module mycrypto:my_crypto_aead_aes_setkey \n");
	if (crypto_authenc_extractkeys(&keys, key, len) != 0)
		goto badkey;
	if (keys.enckeylen > sizeof(ctx->key))
		goto badkey;
	//---------------------------------------------------
	//-----------Lack of authenc hash - set key
	crypto_aead_set_flags(cipher, crypto_aead_get_flags(cipher) &
				    CRYPTO_TFM_RES_MASK);
	/* Now copy the keys into the context */
	memcpy(ctx->key, keys.enckey, keys.enckeylen);
	ctx->keylen = keys.enckeylen;
	//---------- Lack of authenc---------------
	//-----------------------------------------
	memzero_explicit(&keys, sizeof(keys));
	return 0;
badkey:
	crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	memzero_explicit(&keys, sizeof(keys));
	return -EINVAL;
}
static int my_crypto_aead_aes_encrypt(struct aead_request *req)
{
	printk(KERN_INFO " mycrypto_aead_aes_encrypt \n");
	return 0;
}
static int my_crypto_aead_aes_decrypt(struct aead_request *req)
{
	printk(KERN_INFO "mycrypto_aead_aes_decrypt \n");
	return 0;
}
static int my_crypto_aead_cra_init(struct crypto_tfm *tfm)
{
	return 0;
}
static void my_crypto_aead_cra_exit(struct crypto_tfm *tfm)
{
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	memzero_explicit(ctx, tfm->__crt_alg->cra_ctxsize);
}
//----------------------------------------------------------------
static int my_crypto_aead_gcm_aes_setkey(struct crypto_aead *cipher, const u8 *key,unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(cipher);
	// Get/retrieve transformation object
	struct mycrypto_cipher_op *ctx = crypto_tfm_ctx(tfm);
	// Get transformation context 
	struct mycrypto_dev *mydevice = ctx->mydevice;
	struct crypto_aes_ctx aes; 
	/* @aes: The location where the processing key (computed key) will be store*/
	u32 hashkey[AES_BLOCK_SIZE >> 2];
	int ret,i;
	printk(KERN_INFO "GCM_SETKEY");
	ret = crypto_aes_expand_key(&aes, key,len);
	// get key and let it adapt standard criteria of aes, then store it into struct aes.
	if (ret) {
		crypto_aead_set_flags(cipher,CRYPTO_TFM_RES_BAD_KEY_LEN);
		memzero_explicit(&aes, sizeof(aes));
		return ret;
	}
	// copy key stored in aes to ctx
	for(i = 0; i < len /sizeof(u32); i++)
		ctx->key[i] = cpu_to_le32(aes.key_enc[i]);
	ctx->keylen = len;
	//Beside, it is not necessary to fill aes.key_dec.
	//If you wanna continue, just refer to setkey function for skcipher 
	//in file cipher.c (mv_cesa)
	/* Compute hash key by encrypting zeroes with cipher key */
	crypto_cipher_clear_flags(ctx->hkaes, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(ctx->hkaes, crypto_aead_get_flags(cipher) &
				CRYPTO_TFM_REQ_MASK);
	ret = crypto_cipher_setkey(ctx->hkaes, key, len);
	if (ret)
		return ret;

	memset(hashkey, 0, AES_BLOCK_SIZE);
	crypto_cipher_encrypt_one(ctx->hkaes, (u8 *)hashkey, (u8 *)hashkey);

	for (i = 0; i < AES_BLOCK_SIZE / sizeof(u32); i++)
		ctx->ipad[i] = cpu_to_be32(hashkey[i]);

	memzero_explicit(hashkey, AES_BLOCK_SIZE);
	memzero_explicit(&aes, sizeof(aes));
	//free memory
	return 0;
}



//-----------------------------------------------------------------------
//struct AEAD algorithm which is registered after driver probing
struct mycrypto_alg_template mycrypto_alg_cbc_aes = {
    .type = MYCRYPTO_ALG_TYPE_SKCIPHER,
	.alg.skcipher = {
			.setkey = my_crypto_skcipher_aes_setkey,
    		.encrypt = my_crypto_cbc_aes_encrypt,
    		.decrypt = my_crypto_cbc_aes_decrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
    		.ivsize = AES_BLOCK_SIZE,
    		.base = {
        			.cra_name = "cbc(aes)",
					.cra_driver_name = "mycrypto_cbc_aes",
					.cra_priority = 600,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = AES_BLOCK_SIZE,
					.cra_ctxsize = sizeof(struct mycrypto_cipher_op),
					.cra_alignmask = 0,
					.cra_init = my_crypto_skcipher_cra_init,
					.cra_exit = my_crypto_skcipher_cra_exit,
					.cra_module = THIS_MODULE,
    		},
	},
};
struct mycrypto_alg_template mycrypto_alg_gcm_aes = {
    .type = MYCRYPTO_ALG_TYPE_AEAD,
	.alg.aead = {
			.setkey = my_crypto_aead_gcm_aes_setkey,
    		.encrypt = my_crypto_aead_aes_encrypt,
    		.decrypt = my_crypto_aead_aes_decrypt,
    		.ivsize = 12,
			.maxauthsize = SHA256_DIGEST_SIZE,
    		.base = {
        			.cra_name = "gcm(aes)",
					.cra_driver_name = "mycrypto_gcm_aes",
					.cra_priority = 250,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = 1,
					.cra_ctxsize = sizeof(struct mycrypto_cipher_op),
					.cra_alignmask = 0,
					.cra_init = my_crypto_aead_cra_init,
					.cra_exit = my_crypto_aead_cra_exit,
					.cra_module = THIS_MODULE,
    		},
	},
};
struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_ctr_aes = {
    .type = MYCRYPTO_ALG_TYPE_AEAD,
	.alg.aead = {
			.setkey = my_crypto_aead_aes_setkey,
    		.encrypt = my_crypto_aead_aes_encrypt,
    		.decrypt = my_crypto_aead_aes_decrypt,
    		.ivsize = 12,
			.maxauthsize = SHA256_DIGEST_SIZE,
    		.base = {
        			.cra_name = "authenc(hmac(sha256),ctr(aes))",
					.cra_driver_name = "mycrypto_alg_authenc_hmac_sha256_ctr_aes",
					.cra_priority = 250,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = 1,
					.cra_ctxsize = sizeof(struct mycrypto_cipher_op),
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
        			.cra_name = "authenc(hmac(sha256),cbc(aes))",
					.cra_driver_name = "mycrypto_alg_authenc_hmac_sha256_cbc_aes",
					.cra_priority = 300,
					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
					.cra_blocksize = AES_BLOCK_SIZE,
					.cra_ctxsize = sizeof(struct mycrypto_cipher_op),
					.cra_alignmask = 0,
					.cra_init = my_crypto_aead_cra_init,
					.cra_exit = my_crypto_aead_cra_exit,
					.cra_module = THIS_MODULE,
    		},
	},
};


