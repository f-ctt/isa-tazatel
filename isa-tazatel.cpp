#include <iostream>
#include <future>
#include <vector>
#include <getopt.h>
#include <arpa/inet.h>

#include "dns_resolver.h"
#include "whois.h"

using namespace std;

static
void print_help() {
    cout << \
        "\t-q <IPv4/6|hostname> Query\n" << \
        "\t-w <IPv4/6|hostname> WHOIS server>\n" << \
        "\t-d <IPv4/6> DNS server. Optional argument. DNS in /etc/resolv.conf is used by default\n";
}

static
void check_argv(int argc, char *const *argv, char **q, char **w, char **d) {
    const char* const short_opts = "q:w:d:h";
        const option long_opts[] = {
            {"query", required_argument, nullptr, 'q'},
            {"whois", required_argument, nullptr, 'w'},
            {"dns", required_argument, nullptr, 'd'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
        };
    while (true) { 
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
        if (opt == -1)
            break;
        switch (opt) { 
            case 'q':   *q = optarg; break; 
            case 'w':   *w = optarg; break;
            case 'd':   *d = optarg; break;
            case 'h':   print_help(); exit(EXIT_SUCCESS);
            case '?':   print_help(); exit(EXIT_FAILURE);
            default:    print_help(); exit(EXIT_FAILURE);
        }
    }
    if (*q == NULL || *w == NULL) {
        print_help();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *const *argv) {
    vector<future<vector<RecordNode>>> responses;
    future<string> whois_res;
    RecordNodes results;
    string whois_answer;
    sockaddr_storage in;
    unsigned ttl = 2; // the level of recursion
    char *q = NULL, *w = NULL, *d = NULL;

    check_argv(argc, argv, &q, &w, &d);

    if (d != NULL)
      set_dns(d);

    try {
        if (inet_pton(AF_INET, q, &((sockaddr_in *)&in)->sin_addr) == 1) {  
            A ahost = A(((sockaddr_in *)&in)->sin_addr);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return dns_nquery(s, QTYPE::ptr, ttl); }));
            auto str = ahost.toString();
            whois_res = async(launch::async, [str, w]() { return whois_nquery(str, w); });
        } else if (inet_pton(AF_INET6, q, &((sockaddr_in6 *)&in)->sin6_addr) == 1) {
            AAAA ahost = AAAA(((sockaddr_in6 *)&in)->sin6_addr);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return dns_nquery(s, QTYPE::ptr, ttl); }));
            auto str = ahost.toString();
            whois_res = async(launch::async, [str, w]() { return whois_nquery(str, w); });
            cout << str;
        } else {
            responses.push_back(async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::soa, ttl); }));
            auto ares = async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::a, ttl); }); 
            responses.push_back(async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::aaaa, ttl); }));
            responses.push_back(async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::mx, ttl); })); 
            responses.push_back(async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::ns, ttl); }));
            responses.push_back(async(launch::async, [ttl, q]() { return dns_nquery(q, QTYPE::cname, ttl); }));
            // TODO: refactor
            auto arecs = ares.get();    // Get A records first
            if (!arecs.empty()) {
                auto ip = arecs.back().record->toString();
                whois_res = async(launch::async, [ip, w]() { return whois_nquery(ip, w); });
                results.insert(results.end(),   // insert them back to print them later on
                    make_move_iterator(arecs.begin()),
                    make_move_iterator(arecs.end()));
            }
        }
        // TODO: refactor
        for (auto &r : responses) {
            auto res_value = r.get();
            results.insert(results.end(),
                make_move_iterator(res_value.begin()),
                make_move_iterator(res_value.end()));
        }

        if (whois_res.valid())
            whois_answer = whois_res.get();
    }
    catch(const runtime_error &error) {
        cerr << error.what() << endl;
        exit(EXIT_FAILURE);
    }
    catch(...) {
        cerr << "Unknown error" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "\n========= DNS =========\n\n";

    if (!results.empty()) {
        cout << q << endl;
        unsigned cnt = 0;
        for (auto &result : results) {
            cnt++;
            bool last = (cnt == results.size());
            result.printTree("    ", last);
        }
    }

    cout <<"\n========= WHOIS =========\n\n";
    cout << whois_answer;

    return EXIT_SUCCESS;
}