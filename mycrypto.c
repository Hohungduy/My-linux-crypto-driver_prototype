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
#include "cipher.c"
#include "mycrypto.h"
//hello
// struct my_crypto_dev *crypt_dev;
// Adding or Registering algorithm instace of AEAD crypto

static int my_crypto_add_algs(struct aead_alg my_crypto_gcm_aes_alg)
{
 int ret;
 ret = crypto_register_aead(&my_crypto_gcm_aes_alg);
 if(ret)
  {crypto_unregister_aead(&my_crypto_gcm_aes_alg);}
 return ret;
}
//entry point when driver was loaded
static int __init FPGAcrypt_init(void) 
{
 printk(KERN_INFO "Hello, World!\n");
 my_crypto_add_algs(my_crypto_gcm_aes_alg);
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
