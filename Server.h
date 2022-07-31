#ifndef OPENSSLTEST_SERVER_H
#define OPENSSLTEST_SERVER_H

#include "Utils.h"

class Server {
public:
    Server(std::string host, std::string port)
            : host(move(host)), port(move(port)), connected(false) {}

    void connect(Utils::UniquePtr<SSL_CTX> &ctx);

    bool isConnected() const;

    BIO *sslBIO();

private:
    std::string host;
    std::string port;
    bool connected;
    Utils::UniquePtr<BIO> ssl_bio;
};

#endif //OPENSSLTEST_SERVER_H
