
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/aead.h>
#include <linux/crypto.h>
#include <linux/dmapool.h>

enum mycrypto_alg_type {
	MYCRYPTO_ALG_TYPE_SKCIPHER,
	MYCRYPTO_ALG_TYPE_AEAD,
	MYCRYPTO_ALG_TYPE_AHASH,
};
//extern struct my_crypto_cipher_op;
struct mycrypto_alg_template {
	//struct mycrypto_dev *mydevice;
	enum mycrypto_alg_type type;
	union {
		struct skcipher_alg skcipher;
		struct aead_alg aead;
		struct ahash_alg ahash;
	} alg;
};

struct mycrypto_dev{
    struct pci_dev *pdev;
	void __iomem *regs;
    void __iomem *bar[3];
    void __iomem *sram;
	struct device *dev;
    spinlock_t lock;
	struct clk *clk;
	struct clk *reg_clk;
    u32			flags;
    //struct tasklet_struct tasklet;
	struct crypto_queue	queue;
    struct list_head	alg_list;
};
// extern struct aead_alg my_crypto_gcm_aes_alg;
extern struct mycrypto_alg_template mycrypto_alg_authenc_hmac_sha256_cbc_aes;
extern struct mycrypto_alg_template mycrypto_alg_gcm_aes;