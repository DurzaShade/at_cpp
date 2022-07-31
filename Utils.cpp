#include <cstring>
#include <iostream>

#include "Utils.h"

Utils::UniquePtr<BIO> Utils::operator|(Utils::UniquePtr<BIO> lower, Utils::UniquePtr<BIO> upper) {
    BIO_push(upper.get(), lower.release());
    return upper;
}

[[noreturn]] void Utils::print_errors_and_exit(const char *message) {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}

[[noreturn]] void Utils::print_errors_and_throw(const char *message) {
    Utils::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
}

std::string Utils::receive_some_data(BIO *bio) {
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0) {
        Utils::print_errors_and_throw("error in BIO_read");
    } else if (len > 0) {
        return std::string(buffer, len);
    } else if (BIO_should_retry(bio)) {
        return receive_some_data(bio);
    } else {
        Utils::print_errors_and_throw("empty BIO_read");
    }
}

std::string Utils::receive_raw_message(BIO *bio, const char *eol) {
    std::string data = Utils::receive_some_data(bio);
    char *endOfData = strstr(&data[0], eol);
    while (endOfData == nullptr) {
        data += Utils::receive_some_data(bio);
        endOfData = strstr(&data[0], eol);
    }

    int pos = data[0] == '@' ? 1 : 0;

    return data.substr(pos, data.size() - strlen(endOfData) - pos);
}

void Utils::send_raw_request(BIO *bio, const std::string &line, const std::string &eol) {
    std::string request = line + eol;
    std::cout << "SEND: [" << request << "]" << std::endl;
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

SSL *Utils::get_ssl(BIO *bio) {
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        Utils::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

void Utils::verify_the_certificate(SSL *ssl, const std::string &expected_hostname) {
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


