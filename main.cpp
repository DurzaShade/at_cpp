#include <iostream>

#include "Server.h"
#include "AtClient.h"
#include "Crypto.h"


int main() {
    AtClient atClient;

    std::string rootHost = "root.atsign.wtf";
    std::string rootPort = "64";
    Server rootServer(rootHost, rootPort);

    std::string atSign = "alpaca14precise";
    Server secondaryServer = atClient.lookupSecondaryForAtSign(rootServer, atSign);

    std::string challenge = atClient.from(secondaryServer, atSign);

    std::string pkamPemFile = R"(C:\Users\sting\atsign\at_client_java\at_java\at_client\keys\pkam-alpaca.pem)";

    std::vector<unsigned char> signaturebinary = Crypto::GenerateRsaSignByFile(challenge, pkamPemFile);

    std::string b64sig = Crypto::Base64Encode(signaturebinary);
    std::cout << "b64 sig: " << b64sig << std::endl;

    std::string pkamResponse = atClient.pkam(secondaryServer, b64sig);
    std::cout << "pkamResponse: " << pkamResponse << std::endl;

    std::vector<std::string> properties = atClient.scan(secondaryServer);
    for (const auto &prop: properties) {
        std::cout << "prop: " << prop << std::endl;
        std::vector<std::string> tokens = AtClient::parseResponse(prop);
        std::string scanResponse = atClient.llookup(secondaryServer, prop);
        std::cout << "value: " << scanResponse << std::endl;
    }

}

