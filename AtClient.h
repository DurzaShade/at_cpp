#ifndef OPENSSLTEST_ATCLIENT_H
#define OPENSSLTEST_ATCLIENT_H

#include <vector>

#include "Utils.h"
#include "Server.h"

class AtClient {
public:
    AtClient();

    Server lookupSecondaryForAtSign(Server &rootServer, const std::string &atSign);

    static std::vector<std::string> parseResponse(const std::string &response);

    std::vector<std::string> scan(Server &secondaryServer);

    std::string lookup(Server &secondaryServer, const std::string &property);

    std::string llookup(Server &secondaryServer, const std::string &property);

    std::string plookup(Server &secondaryServer, const std::string &property);

    std::string from(Server &secondaryServer, const std::string &atSign);

    std::string pkam(Server &secondaryServer, const std::string &signature);


private:
    Utils::UniquePtr<SSL_CTX> ctx;
};

#endif //OPENSSLTEST_ATCLIENT_H
