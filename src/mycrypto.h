
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/aead.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/crypto.h>
#include <linux/dmapool.h>

#define BUFFER_SIZE 128
enum mycrypto_alg_type {
	MYCRYPTO_ALG_TYPE_SKCIPHER,
	MYCRYPTO_ALG_TYPE_AEAD,
	MYCRYPTO_ALG_TYPE_AHASH,
};

//extern struct my_crypto_cipher_op;
struct mycrypto_alg_template {
	struct mycrypto_dev *mydevice;
	enum mycrypto_alg_type type;
	union {
		struct skcipher_alg skcipher;
		struct aead_alg aead;
		struct ahash_alg ahash;
	} alg;
};

struct mycrypto_work_data {
	struct work_struct work;
	struct mycrypto_dev *mydevice;
};
/**
 * struct mycrypto_dev
 * @pdev:       infor pci device
 * @regs:		engine registers
 * @sram:		SRAM memory region
 * @sram_dma:   DMA address of the SRAM memory region
 * @lock:        lock key uses for spin lock
 * @clk: 
 * @regs_clk:
 * @flags:
 * @req:		current crypto request
 * @queue:		fifo of the pending crypto requests
 * @complete_queue:	fifo of the processed requests by the engine
 *
 * Structure storing CESA engine information.
 */
struct mycrypto_dev{
    struct pci_dev *pdev;
	void __iomem *regs;
    void __iomem *bar[3];
    void __iomem *sram;
	struct device *dev;
    spinlock_t queue_lock;
	struct clk *clk;
	struct clk *reg_clk;
    u32			flags;
	char *buffer;
	/* Store for current requests when bailing out of the dequeueing
	 * function when no enough resources are available.
	 */
	struct crypto_async_request *req;// filled in dequeue
	struct crypto_async_request *backlog;// filled in dequeue
	/*need   work queue or we can use dequeue function in enqueue function*/
	struct workqueue_struct *workqueue;
	struct mycrypto_work_data work_data;
	/* use for callback function*/
    struct tasklet_struct tasklet;
	/* store request in crypto queue*/
	struct crypto_queue	queue;
	struct list_head complete_queue; 
    struct list_head	alg_list;
	struct timer_list mycrypto_ktimer;
	
};
/**
 * struct mycrypto_req_operations - request operations
 * @handle_request:	launch the crypto operation on the next chunk ((should return 0 if the
 *		operation, -EINPROGRESS if it needs more steps or an error
 *		code))
 * @handle_result:complete the request, i.e copy result or context from device when needed 
 * then cleanup the. check error code and theen clean up the crypto request, then retrieve call-back
 * function
 */
struct mycrypto_req_operation {
	
	int (*handle_request)(struct crypto_async_request *req);
	int (*handle_result)(struct crypto_async_request *req,bool *should_complete);
	
};
// extern struct aead_alg my_crypto_gcm_aes_alg;
extern struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_cbc_aes;
extern struct mycrypto_alg_template mycrypto_alg_gcm_aes;
extern struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_ctr_aes;
extern struct mycrypto_alg_template mycrypto_alg_cbc_aes;