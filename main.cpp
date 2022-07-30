#include <memory>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

namespace my {

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
    using UniquePtr = unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

    my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper) {
        BIO_push(upper.get(), lower.release());
        return upper;
    }

    class StringBIO {
        string str_;
        my::UniquePtr<BIO_METHOD> methods_;
        my::UniquePtr<BIO> bio_;
    public:
        StringBIO(StringBIO &&) = delete;

        StringBIO &operator=(StringBIO &&) = delete;

        explicit StringBIO() {
            methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
            if (methods_ == nullptr) {
                throw runtime_error("StringBIO: error in BIO_meth_new");
            }
            BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
                auto *str = reinterpret_cast<string *>(BIO_get_data(bio));
                str->append(data, len);
                return len;
            });
            bio_.reset(BIO_new(methods_.get()));
            if (bio_ == nullptr) {
                throw runtime_error("StringBIO: error in BIO_new");
            }
            BIO_set_data(bio_.get(), &str_);
            BIO_set_init(bio_.get(), 1);
        }

        BIO *bio() { return bio_.get(); }

        string str() &&{ return move(str_); }
    };

    [[noreturn]] void print_errors_and_exit(const char *message) {
        fprintf(stderr, "%s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    [[noreturn]] void print_errors_and_throw(const char *message) {
        my::StringBIO bio;
        ERR_print_errors(bio.bio());
        throw runtime_error(string(message) + "\n" + move(bio).str());
    }

    string receive_some_data(BIO *bio) {
        char buffer[1024];
        int len = BIO_read(bio, buffer, sizeof(buffer));
        if (len < 0) {
            my::print_errors_and_throw("error in BIO_read");
        } else if (len > 0) {
            return string(buffer, len);
        } else if (BIO_should_retry(bio)) {
            return receive_some_data(bio);
        } else {
            my::print_errors_and_throw("empty BIO_read");
        }
    }

    string receive_raw_message(BIO *bio, const char *eol = "\r\n") {
        string data = my::receive_some_data(bio);
        char *endOfData = strstr(&data[0], eol);
        while (endOfData == nullptr) {
            data += my::receive_some_data(bio);
            endOfData = strstr(&data[0], eol);
        }

        int pos = data[0] == '@' ? 1 : 0;
        cout << "data :{"<< data << "}"<< endl;
        cout << "length of data :" << data.size() << endl;
        cout << "end of data:{" <<endOfData <<"}"<< endl;
        cout << "length of end of data :" << strlen(endOfData) << endl;

        return data.substr(pos, data.size() - strlen(endOfData) - pos);
    }

    void send_raw_request(BIO *bio, const string &line, const string & eol = "\r\n") {
        string request = line + eol;
        cout << "SEND: [" << request << "]" << endl;
        BIO_write(bio, request.data(), request.size());
        BIO_flush(bio);
    }

    SSL *get_ssl(BIO *bio) {
        SSL *ssl = nullptr;
        BIO_get_ssl(bio, &ssl);
        if (ssl == nullptr) {
            my::print_errors_and_exit("Error in BIO_get_ssl");
        }
        return ssl;
    }

    void verify_the_certificate(SSL *ssl, const string &expected_hostname) {
        int err = SSL_get_verify_result(ssl);
        if (err != X509_V_OK) {
            const char *message = X509_verify_cert_error_string(err);
            fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
            exit(1);
        }
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert == nullptr) {
            fprintf(stderr, "No certificate was presented by the server\n");
            exit(1);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
            fprintf(stderr, "Certificate verification error: X509_check_host\n");
            exit(1);
        }
#else
        // X509_check_host is called automatically during verification,
        // because we set it up in main().
        (void) expected_hostname;
#endif
    }

} // namespace my

class Server {
public:
    Server(string host, string port)
            : host(move(host)), port(move(port)), connected(false) {}

    void connect(my::UniquePtr<SSL_CTX> &ctx) {
        string host_port = host + ":" + port;
        auto bio = my::UniquePtr<BIO>(BIO_new_connect(host_port.c_str()));
        if (bio == nullptr) {
            my::print_errors_and_exit("Error in BIO_new_connect");
        }
        if (BIO_do_connect(bio.get()) <= 0) {
            my::print_errors_and_exit("Error in BIO_do_connect");
        }

        ssl_bio = move(bio)
                  | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
        SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), host.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        SSL_set1_host(my::get_ssl(ssl_bio.get()), host.c_str());
#endif
        if (BIO_do_handshake(ssl_bio.get()) <= 0) {
            my::print_errors_and_exit("Error in BIO_do_handshake");
        }

        // TODO: need to verify server certificate
        // my::verify_the_certificate(my::get_ssl(ssl_bio.get()), host.c_str());

        connected = true;
    }

    bool isConnected() const {
        return connected;
    }

    BIO *sslBIO() {
        return ssl_bio.get();
    }

private:
    string host;
    string port;
    bool connected;
    my::UniquePtr<BIO> ssl_bio;
};

class AtClient {
public:
    AtClient() {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#endif

        /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
        ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif
        if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
            my::print_errors_and_exit("Error setting up trust store");
        }
    }

    Server lookupSecondaryForAtSign(Server &rootServer, const string &atSign) {
        if (!rootServer.isConnected()) {
            rootServer.connect(ctx);
        }

        auto ssl_bio = rootServer.sslBIO();
        my::send_raw_request(ssl_bio, atSign);
        string response = my::receive_raw_message(ssl_bio);
        printf("received response : %s\n", response.c_str());

        vector<string> tokens = parseResponse(response);

        return {tokens[0], tokens[1]};
    }

    static vector<string> parseResponse(const string &response) {
        istringstream ss(response);
        string token;
        vector<string> tokens;
        while (getline(ss, token, ':')) {
            tokens.push_back(token);
        }
        return tokens;
    }

    vector<string> scan(Server &secondaryServer) {
        if (!secondaryServer.isConnected()) {
            secondaryServer.connect(ctx);
        }

        auto ssl_bio = secondaryServer.sslBIO();
        my::send_raw_request(ssl_bio, "scan");
        string response = my::receive_raw_message(ssl_bio, "\n@");
        printf("received response : %s\n", response.c_str());
        json json_response = json::parse(response.substr(strlen("data:"), response.size()));
        return json_response.get<vector<string>>();
    }

    string lookup(Server &secondaryServer, const string &property) {
        if (!secondaryServer.isConnected()) {
            secondaryServer.connect(ctx);
        }

        string request = "llookup:" + property;
        auto ssl_bio = secondaryServer.sslBIO();
        my::send_raw_request(ssl_bio, request);
        string response = my::receive_raw_message(ssl_bio, "\n");
        printf("received response : %s\n", response.c_str());

        vector<string> tokens = parseResponse(response);
        return tokens[1];
    }

    string from(Server &secondaryServer, const string &atSign) {
        if (!secondaryServer.isConnected()) {
            secondaryServer.connect(ctx);
        }

        auto ssl_bio = secondaryServer.sslBIO();
        my::send_raw_request(ssl_bio, "from:@" + atSign, "\n");
        string response = my::receive_raw_message(ssl_bio, "\n");
        printf("received response : %s\n", response.c_str());


        return response.substr(strlen("data:"), response.size());
    }

    string pkam(Server &secondaryServer, const string &signature) {
        if (!secondaryServer.isConnected()) {
            secondaryServer.connect(ctx);
        }

        auto ssl_bio = secondaryServer.sslBIO();
        my::send_raw_request(ssl_bio, "pkam:" + signature, "\n");
        string response = my::receive_raw_message(ssl_bio, "\n");
        printf("received response : %s\n", response.c_str());


        return response;
    }


private:
    my::UniquePtr<SSL_CTX> ctx;
};

RSA *createPrivateRSA(const string &key) {
    RSA *rsa = nullptr;
    const char *c_string = key.c_str();
    BIO *keybio = BIO_new_mem_buf((void *) c_string, -1);
    if (keybio == nullptr) {
        return nullptr;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr);
    return rsa;
}

bool RSASign(RSA *rsa,
             const unsigned char *Msg,
             size_t MsgLen,
             unsigned char **signature,
             size_t *signatureLen) {
    EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY *priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx, nullptr, EVP_sha256(), nullptr, priKey) <= 0) {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, nullptr, signatureLen) <= 0) {
        return false;
    }
    *signature = (unsigned char *) malloc(*signatureLen);
    if (EVP_DigestSignFinal(m_RSASignCtx, *signature, signatureLen) <= 0) {
        return false;
    }
    EVP_MD_CTX_destroy(m_RSASignCtx);
    return true;
}

void Base64Encode(const unsigned char *buffer,
                  size_t length,
                  char **base64Text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    *base64Text = (*bufferPtr).data;
}

string signMessage(const string &privateKey, const string &plainText) {
    RSA *privateRSA = createPrivateRSA(privateKey);
    unsigned char *encMessage;
    char *base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char *) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}

std::vector<char> GenerateRsaSignByString(const std::string& message,
                                          const std::string& prikey) {
    OpenSSL_add_all_algorithms();
    BIO* in = BIO_new_mem_buf((void*)prikey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return std::vector<char>();
    }

    RSA* rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<char> sign;
    sign.resize(size);

    int ret =
            RSA_sign(NID_md5, (const unsigned char*)message.c_str(),
                     message.length(), (unsigned char*)sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<char>();
    }
    return sign;
}

std::vector<unsigned char> GenerateRsaSignByFile(const std::string& message,
                                        const std::string& pri_filename) {
    OpenSSL_add_all_algorithms();
    BIO* in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return std::vector<unsigned char>();
    }
    BIO_read_filename(in, pri_filename.c_str());
    RSA* rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<unsigned char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<unsigned char> sign;
    sign.resize(size);

    // Buffer to hold the calculated digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message.c_str(), message.length());
    SHA256_Final(digest, &ctx);

    int ret =
            RSA_sign(NID_sha256   , (const unsigned char*)digest,
                     SHA256_DIGEST_LENGTH, (unsigned char*)sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<unsigned char>();
    }
    return sign;
}

namespace {
    struct BIOFreeAll { void operator()(BIO* p) { BIO_free_all(p); } };
}
std::string Base64Encode(const std::vector<unsigned char>& binary)
{
    std::unique_ptr<BIO,BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), sink);
    BIO_write(b64.get(), binary.data(), binary.size());
    BIO_flush(b64.get());
    const char* encoded;
    const long len = BIO_get_mem_data(sink, &encoded);
    return std::string(encoded, len);
}

int main() {
    AtClient atClient;

    string rootHost = "root.atsign.wtf";
    string rootPort = "64";
    Server rootServer(rootHost, rootPort);

    string atSign = "alpaca14precise";
    Server secondaryServer = atClient.lookupSecondaryForAtSign(rootServer, atSign);

    string challenge = atClient.from(secondaryServer, atSign);
    cout << "challenge: [" << challenge << "]" << endl;

    string pkamPemFile = R"(C:\Users\sting\atsign\at_client_java\at_java\at_client\keys\pkam-alpaca.pem)";

    vector<unsigned char> signaturebinary = GenerateRsaSignByFile(challenge, pkamPemFile);

    string b64sig = Base64Encode(signaturebinary);
    cout << "b64 sig: " << b64sig << endl;

    string pkamResponse = atClient.pkam(secondaryServer, b64sig);
    cout << "pkamResponse: " << pkamResponse << endl;

    vector<string> properties = atClient.scan(secondaryServer);
    for (const auto &prop: properties) {
        cout << "prop: " << prop << endl;
        vector<string> tokens = AtClient::parseResponse(prop);
        string scanResponse = atClient.lookup(secondaryServer, prop);
        cout << "value: " << scanResponse << endl;
    }

}

