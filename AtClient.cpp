#include <nlohmann/json.hpp>

#include "Utils.h"
#include "Server.h"
#include "AtClient.h"

AtClient::AtClient() {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = Utils::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    ctx = Utils::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
        Utils::print_errors_and_exit("Error setting up trust store");
    }
}

Server AtClient::lookupSecondaryForAtSign(Server &rootServer, const std::string &atSign) {
    if (!rootServer.isConnected()) {
        rootServer.connect(ctx);
    }

    auto ssl_bio = rootServer.sslBIO();
    Utils::send_raw_request(ssl_bio, atSign);
    std::string response = Utils::receive_raw_message(ssl_bio);
    printf("received response : %s\n", response.c_str());

    std::vector<std::string> tokens = AtClient::parseResponse(response);

    return {tokens[0], tokens[1]};
}

std::vector<std::string> AtClient::parseResponse(const std::string &response) {
    std::istringstream ss(response);
    std::string token;
    std::vector<std::string> tokens;
    while (getline(ss, token, ':')) {
        tokens.push_back(token);
    }
    return tokens;
}

std::vector<std::string> AtClient::scan(Server &secondaryServer) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, "scan");
    std::string response = Utils::receive_raw_message(ssl_bio, "\n@");
    printf("received response : %s\n", response.c_str());
    nlohmann::json json_response = nlohmann::json::parse(response.substr(strlen("data:"), response.size()));
    return json_response.get<std::vector<std::string>>();
}

std::string AtClient::lookup(Server &secondaryServer, const std::string &property) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    std::string request = "lookup:" + property;
    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, request);
    std::string response = Utils::receive_raw_message(ssl_bio, "\n");
    printf("received response : %s\n", response.c_str());

    std::vector<std::string> tokens = parseResponse(response);
    return tokens[1];
}

std::string AtClient::llookup(Server &secondaryServer, const std::string &property) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    std::string request = "llookup:" + property;
    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, request);
    std::string response = Utils::receive_raw_message(ssl_bio, "\n");
    printf("received response : %s\n", response.c_str());

    std::vector<std::string> tokens = parseResponse(response);
    return tokens[1];
}

std::string AtClient::plookup(Server &secondaryServer, const std::string &property) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    std::string request = "plookup:" + property;
    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, request);
    std::string response = Utils::receive_raw_message(ssl_bio, "\n");
    printf("received response : %s\n", response.c_str());

    std::vector<std::string> tokens = parseResponse(response);
    return tokens[1];
}

std::string AtClient::from(Server &secondaryServer, const std::string &atSign) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, "from:@" + atSign, "\n");
    std::string response = Utils::receive_raw_message(ssl_bio, "\n");
    printf("received response : %s\n", response.c_str());


    return response.substr(strlen("data:"), response.size());
}

std::string AtClient::pkam(Server &secondaryServer, const std::string &signature) {
    if (!secondaryServer.isConnected()) {
        secondaryServer.connect(ctx);
    }

    auto ssl_bio = secondaryServer.sslBIO();
    Utils::send_raw_request(ssl_bio, "pkam:" + signature, "\n");
    std::string response = Utils::receive_raw_message(ssl_bio, "\n");
    printf("received response : %s\n", response.c_str());


    return response;
}




