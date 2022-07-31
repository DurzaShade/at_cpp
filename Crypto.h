#ifndef OPENSSLTEST_CRYPTO_H
#define OPENSSLTEST_CRYPTO_H

#include <vector>
#include <openssl/ssl.h>

class Crypto {
private:
    struct BIOFreeAll {
        void operator()(BIO *p) { BIO_free_all(p); }
    };

public:
    static std::vector<unsigned char> GenerateRsaSignByFile(const std::string &message,
                                                            const std::string &pri_filename);

    static std::string Base64Encode(const std::vector<unsigned char> &binary);

};

#endif //OPENSSLTEST_CRYPTO_H
