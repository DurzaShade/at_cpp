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
        return data.substr(pos, data.size() - strlen(endOfData) - 1);
    }

    void send_raw_request(BIO *bio, const string &line) {
        string request = line + "\r\n";
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

        vector<string> tokens = parseResponse(response);

        json json_response = json::parse(tokens[1]);
        return json_response.get<vector<string>>();
    }

    string lookup(Server &secondaryServer, const string &property) {
        if (!secondaryServer.isConnected()) {
            secondaryServer.connect(ctx);
        }

        string request = "lookup:" + property;
        auto ssl_bio = secondaryServer.sslBIO();
        my::send_raw_request(ssl_bio, request);
        string response = my::receive_raw_message(ssl_bio, "\n");
        printf("received response : %s\n", response.c_str());

        vector<string> tokens = parseResponse(response);
        return tokens[1];
    }


private:
    my::UniquePtr<SSL_CTX> ctx;
};


int main() {
    AtClient atClient;

    string rootHost = "root.atsign.wtf";
    string rootPort = "64";
    Server rootServer(rootHost, rootPort);

    string atSign = "northerncomputer";
    Server secondaryServer = atClient.lookupSecondaryForAtSign(rootServer, atSign);

    vector<string> properties = atClient.scan(secondaryServer);
    for (const auto &prop: properties) {
        cout << "prop: " << prop << endl;
        string scanResponse = atClient.lookup(secondaryServer, prop);
        cout << "value: " << scanResponse << endl;
    }
}

