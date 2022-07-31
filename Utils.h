#ifndef OPENSSLTEST_UTILS_H
#define OPENSSLTEST_UTILS_H

#include <cstring>
#include <stdexcept>
#include <string>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace Utils {

    template<class T>
    struct DeleterOf;

    template<>
    struct DeleterOf<BIO> {
        void operator()(BIO *p) const { BIO_free_all(p); }
    };

    template<>
    struct DeleterOf<BIO_METHOD> {
        void operator()(BIO_METHOD *p) const { BIO_meth_free(p); }
    };

    template<>
    struct DeleterOf<SSL_CTX> {
        void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
    };

    template<class OpenSSLType>
    using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

    UniquePtr<BIO> operator|(UniquePtr<BIO> lower, UniquePtr<BIO> upper);

    class StringBIO {
        std::string str_;
        Utils::UniquePtr<BIO_METHOD> methods_;
        Utils::UniquePtr<BIO> bio_;
    public:
        StringBIO(StringBIO &&) = delete;

        StringBIO &operator=(StringBIO &&) = delete;

        explicit StringBIO() {
            methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
            if (methods_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_meth_new");
            }
            BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
                auto *str = reinterpret_cast<std::string *>(BIO_get_data(bio));
                str->append(data, len);
                return len;
            });
            bio_.reset(BIO_new(methods_.get()));
            if (bio_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_new");
            }
            BIO_set_data(bio_.get(), &str_);
            BIO_set_init(bio_.get(), 1);
        }

        BIO *bio() { return bio_.get(); }

        std::string str() &&{ return move(str_); }
    };

    [[noreturn]] void print_errors_and_exit(const char *message);

    [[noreturn]] void print_errors_and_throw(const char *message);

    std::string receive_some_data(BIO *bio);

    std::string receive_raw_message(BIO *bio, const char *eol = "\r\n") ;

    void send_raw_request(BIO *bio, const std::string &line, const std::string & eol = "\r\n");

    SSL *get_ssl(BIO *bio);

    void verify_the_certificate(SSL *ssl, const std::string &expected_hostname);

} // namespace Utils

#endif //OPENSSLTEST_UTILS_H
