#include "Server.h"

void Server::connect(Utils::UniquePtr<SSL_CTX> &ctx) {
    std::string host_port = host + ":" + port;
    auto bio = Utils::UniquePtr<BIO>(BIO_new_connect(host_port.c_str()));
    if (bio == nullptr) {
        Utils::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        Utils::print_errors_and_exit("Error in BIO_do_connect");
    }

    ssl_bio = move(bio)
              | Utils::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
    SSL_set_tlsext_host_name(Utils::get_ssl(ssl_bio.get()), host.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(Utils::get_ssl(ssl_bio.get()), host.c_str());
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        Utils::print_errors_and_exit("Error in BIO_do_handshake");
    }

    // TODO: need to verify server certificate
    // Utils::verify_the_certificate(Utils::get_ssl(ssl_bio.get()), host.c_str());

    connected = true;
}

bool Server::isConnected() const {
    return connected;
}

BIO *Server::sslBIO() {
    return ssl_bio.get();
}


