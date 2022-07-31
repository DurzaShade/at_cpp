#include <nlohmann/json.hpp>

#include "Utils.h"
#include "Server.h"
#include "AtClient.h"

Server AtClient::lookupSecondaryForAtSign(Server &rootServer, const std::string &atSign) {
    std::string response = rootServer.executeCommand(atSign);
    printf("received response : %s\n", response.c_str());
    std::vector<std::string> tokens = Utils::parseResponse(response);
    return {tokens[0], tokens[1]};
}

std::vector<std::string> AtClient::scan(Server &secondaryServer) {
    std::string response = secondaryServer.executeCommand("scan", "\r\n", "\n@");
    printf("received response : %s\n", response.c_str());
    nlohmann::json json_response = nlohmann::json::parse(response.substr(strlen("data:"), response.size()));
    return json_response.get<std::vector<std::string>>();
}

std::string AtClient::lookup(Server &secondaryServer, const std::string &property) {
    std::string lookupProperty = "lookup:" + property;
    std::string response = secondaryServer.executeCommand(lookupProperty, "\r\n", "\n");
    printf("received response : %s\n", response.c_str());
    std::vector<std::string> tokens = Utils::parseResponse(response);
    return tokens[1];
}

std::string AtClient::llookup(Server &secondaryServer, const std::string &property) {
    std::string llookupProperty = "llookup:" + property;
    std::string response = secondaryServer.executeCommand(llookupProperty, "\r\n", "\n");
    printf("received response : %s\n", response.c_str());
    std::vector<std::string> tokens = Utils::parseResponse(response);
    return tokens[1];
}

std::string AtClient::plookup(Server &secondaryServer, const std::string &property) {
    std::string plookupProperty = "plookup:" + property;
    std::string response = secondaryServer.executeCommand(plookupProperty, "\r\n", "\n");
    printf("received response : %s\n", response.c_str());

    std::vector<std::string> tokens = Utils::parseResponse(response);
    return tokens[1];
}

std::string AtClient::from(Server &secondaryServer, const std::string &atSign) {
    std::string fromCommand = "from:@" + atSign;
    std::string response = secondaryServer.executeCommand(fromCommand, "\n", "\n");
    printf("received response : %s\n", response.c_str());
    return response.substr(strlen("data:"), response.size());
}

std::string AtClient::pkam(Server &secondaryServer, const std::string &signature) {
    std::string pkamCommand = "pkam:" + signature;
    std::string response = secondaryServer.executeCommand(pkamCommand, "\n", "\n");
    printf("received response : %s\n", response.c_str());
    return response;
}
