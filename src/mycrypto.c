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
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kthread.h>
#include <linux/mbus.h>
//#include "cipher.c"
#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <crypto/des.h>
#include <crypto/aead.h>
#include <crypto/internal/aead.h>
#include <crypto/sha.h>
#include "mycrypto.h"


// Adding or Registering algorithm instace of AEAD crypto
static struct mycrypto_alg_template *mycrypto_algs[] ={
	&mycrypto_alg_authenc_hmac_sha256_cbc_aes,
	&mycrypto_alg_gcm_aes,
};
// struct my_crypto_cipher_op{
//  void *src;
//  void *dst;
//  u32 dir;
//  u32 flags;
//  u32 mode;
//  int len;
//  u8 key[AES_KEYSIZE_128];
//  u8 *iv;
//  u32 keylen;
 
// };
// // Note the cra_aligmask
// //struct AEAD algorithm which is registered after driver probing
// static int my_crypto_aead_aes_setkey(struct crypto_aead *cipher, const u8 *key,unsigned int len)
// {
// 	return 0;
// }
// static int my_crypto_aead_aes_encrypt(struct aead_request *req)
// {
// 	printk(KERN_INFO "hello world my_crypto_aead_aes_encrypt \n");
// 	return 0;
// }
// static int my_crypto_aead_aes_decrypt(struct aead_request *req)
// {
// 	printk(KERN_INFO "hello world my_crypto_aead_aes_decrypt \n");
// 	return 0;
// }
// static int my_crypto_aead_cra_init(struct crypto_tfm *tfm)
// {
// 	return 0;
// }
// static void my_crypto_aead_cra_exit(struct crypto_tfm *tfm)
// {
	
// }
// struct mycrypto_alg_template mycrypto_alg_gcm_aes = {
//     .type = MYCRYPTO_ALG_TYPE_AEAD,
// 	.alg.aead = {
// 			.setkey = my_crypto_aead_aes_setkey,
//     		.encrypt = my_crypto_aead_aes_encrypt,
//     		.decrypt = my_crypto_aead_aes_decrypt,
//     		.ivsize = 12,
// 			.maxauthsize = SHA256_DIGEST_SIZE,
//     		.base = {
//         			.cra_name = "authenc(hmac(sha256),ctr(aes))",
// 					.cra_driver_name = "mycrypto_gcm_aes",
// 					.cra_priority = 250,
// 					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
// 					.cra_blocksize = 1,
// 					.cra_ctxsize = sizeof(struct my_crypto_cipher_op),
// 					.cra_alignmask = 0,
// 					.cra_init = my_crypto_aead_cra_init,
// 					.cra_exit = my_crypto_aead_cra_exit,
// 					.cra_module = THIS_MODULE,
//     		},
// 	},
// };

// struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_cbc_aes = {
//     .type = MYCRYPTO_ALG_TYPE_AEAD,
// 	.alg.aead = {
// 			.setkey = my_crypto_aead_aes_setkey,
//     		.encrypt = my_crypto_aead_aes_encrypt,
//     		.decrypt = my_crypto_aead_aes_decrypt,
//     		.ivsize = AES_BLOCK_SIZE,
// 			.maxauthsize = SHA256_DIGEST_SIZE,
//     		.base = {
//         			.cra_name = "authenc(hmac(sha256),cbc(aes))",
// 					.cra_driver_name = "mycrypto_alg_authenc_hmac_sha256_cbc_aes",
// 					.cra_priority = 300,
// 					.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
// 					.cra_blocksize = AES_BLOCK_SIZE,
// 					.cra_ctxsize = sizeof(struct my_crypto_cipher_op),
// 					.cra_alignmask = 0,
// 					.cra_init = my_crypto_aead_cra_init,
// 					.cra_exit = my_crypto_aead_cra_exit,
// 					.cra_module = THIS_MODULE,
//     		},
// 	},
// };
// static int my_crypto_add_algs(struct mycrypto_dev *mydevice)
static int my_crypto_add_algs(void)
{
 int i,j,ret = 0;
 for (i = 0; i < ARRAY_SIZE(mycrypto_algs); i++) {
		//mycrypto_algs[i]->mydevice = mydevice;
		if (mycrypto_algs[i]->type == MYCRYPTO_ALG_TYPE_SKCIPHER)
			ret = crypto_register_skcipher(&mycrypto_algs[i]->alg.skcipher);
		else if (mycrypto_algs[i]->type == MYCRYPTO_ALG_TYPE_AEAD)
			ret = crypto_register_aead(&mycrypto_algs[i]->alg.aead);
		else
			ret = crypto_register_ahash(&mycrypto_algs[i]->alg.ahash);
 }
//  ret = crypto_register_aead(alg);
 if(ret)
	goto fail;
 return 0;
fail:
	//   crypto_unregister_aead(alg);
 for (j = 0; j < i; j++) {
		if (mycrypto_algs[j]->type == MYCRYPTO_ALG_TYPE_SKCIPHER)
			crypto_unregister_skcipher(&mycrypto_algs[j]->alg.skcipher);
		else if (mycrypto_algs[j]->type == MYCRYPTO_ALG_TYPE_AEAD)
			crypto_unregister_aead(&mycrypto_algs[j]->alg.aead);
		else
			crypto_unregister_ahash(&mycrypto_algs[j]->alg.ahash);
	}
	  return ret;
}
//entry point when driver was loaded
static int __init FPGAcrypt_init(void) 
{
 //struct mycrypto_dev *mydevice;
 int ret;
 printk(KERN_INFO "Hello, World!\n");
 ret = my_crypto_add_algs();
 if (ret){
	 printk(KERN_INFO "Failed to register algorithms\n");
 }
 return 0;
}

//entry point when driver was remove
static void __exit FPGAcrypt_exit(void) 
{
 printk(KERN_INFO "Goodbye, World!\n");
}
module_init(FPGAcrypt_init);
module_exit(FPGAcrypt_exit);

/*
static struct pci_driver my_pcie_crypto_driver = {
	.name = "my_pcie_crypto_driver",
	.id_table = pcie_crypto_tpls,
	.probe = my_pcie_crypto_probe,
	.remove = my_pcie_crypto_remove,
};
*/
//module_pci_driver(geode_aes_driver)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Duy H.Ho");
MODULE_DESCRIPTION("A prototype Linux module for crypto in FPGA-PCIE card");
MODULE_VERSION("0.01");