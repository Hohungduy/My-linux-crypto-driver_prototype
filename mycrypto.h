
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/aead.h>
#include <linux/crypto.h>
#include <linux/dmapool.h>

// struct my_crypto_dev
// {
//     int
// }
//extern struct my_crypto_cipher_op;
extern struct aead_alg my_crypto_gcm_aes_alg;