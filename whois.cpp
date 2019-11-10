#include "whois.h"
#include <sys/socket.h>
#include <string.h>
#include <sstream>
#include <algorithm>        // transform
#include <arpa/inet.h>
#include <unistd.h>         // close

#include "dns_resolver.h"
#include "helpers.h"

using namespace std;

static
int set_whost(string whost, sockaddr_storage *in, bool redirection = false) {
    if (!redirection) {
        if (inet_pton(AF_INET, whost.c_str(), &((struct sockaddr_in *)in)->sin_addr) != 1) {
            if (inet_pton(AF_INET6, whost.c_str(), &((struct sockaddr_in6 *)in)->sin6_addr) == 1) {
                ((sockaddr_in6 *)in)->sin6_port = htons(43);
                in->ss_family = AF_INET6;
                return AF_INET6;
            }
        } else {
            ((sockaddr_in *)in)->sin_port = htons(43);
            in->ss_family = AF_INET;
            return AF_INET;
        }
    }
    auto response = dns_nquery(whost, QTYPE::a, 0);
    for (auto &res : response) {
        if (res.record->qtype() == QTYPE::a) {
            sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_addr = dynamic_cast<A*>(res.record.get())->inaddr();
            addr.sin_family = AF_INET;
            addr.sin_port = htons(43);
            memcpy(in, &addr, sizeof(sockaddr_in));
            return AF_INET;
        }
    }
    return -1;
}

__attribute__((__always_inline__))
static
void erase_all(string &str, const string &chars = "\n\r\n \\") {
    for (auto ch: chars)
        str.erase(std::remove(str.begin(), str.end(), ch), str.end());
}

string whois_nquery(string ip, string whost) {
    int ret, sock, rsize, insize = rsize = sock = ret = 0;
    bool redirection = false;
    char buf[1500] = {0}; // ethernet's datagram size
    string response;
    sockaddr_storage in;
    ip.append("\r\n");

    do {
        response.clear();
        memset(&buf, 0, sizeof(buf)); 
        memset(&in, 0, sizeof(in));
        if ((ret = set_whost(whost, &in, redirection)) < 0)
            throw runtime_error(string() + "whost: " + strerror(errno));
        redirection = false;
        insize = (ret == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
        if ((sock = socket(ret, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            throw runtime_error(strerror(errno));
        }
        if (connect(sock , (sockaddr *)&in, insize)) {
            throw runtime_error(string() + "whost: " + strerror(errno));
        }
        if (send(sock, ip.c_str(), ip.size(), 0) < 0)
            throw runtime_error(strerror(errno));
        while ((rsize = recv(sock, buf, sizeof(buf), 0)) > 0) {
            size_t pos = string::npos;
            istringstream stream;
            stream.str(buf);
            for (string line; getline(stream, line); ) {
                transform(line.begin(), line.end(), line.begin(),
                    [](unsigned char c){ return tolower(c); });
                if ((pos = line.find("whois:")) != string::npos) {
                    erase_all(line);
                    whost = line.substr(pos + strlen("whois:"), line.size());
                    redirection = true;
                }
                else if ((pos = line.find("whois server:")) != string::npos) {
                    erase_all(line);
                    whost = line.substr(pos + strlen("whois server:"), line.size());
                    redirection = true;
                } 
            }
            response.insert(response.end(), buf, buf + rsize);
        }
        if (rsize < 0) {
            throw runtime_error(strerror(errno));
        }
        close(sock);
        #ifdef DEBUG
        if (redirection) STDOUT("[REDIRECTING to " << whost << "...]");
        #endif
    } while (redirection);
    return response;
}