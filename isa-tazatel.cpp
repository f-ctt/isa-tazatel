#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <thread>
#include <future>
#include <vector>
#include <tuple>
#include <cstring>
#include <unordered_map>
#include <functional>

using namespace std;

#define STDERR(x) do { cerr << __func__ << ":" <<__LINE__ << ": " << x << endl; } while (0)
#define STDOUT(x) do { cout << x << endl; } while (0)

class Addrinfo {

    private:
        struct addrinfo *result;

    public:
        Addrinfo(const char *node) {
            addrinfo hints;
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_INET;        // IPv4 and IPv6 //FIXME: IPv4 for now
            hints.ai_socktype = SOCK_DGRAM;     // Datagram socket
            hints.ai_flags |= AI_CANONNAME;     // canonname in result's root

            int res = 0;
            if ((res = getaddrinfo(node, NULL, &hints, &result))) {
                STDERR(node << " " << gai_strerror(res));
                throw exception();
            }
        }

        const char *name() {
            return result->ai_canonname;
        }

        void get_in4addr(struct in_addr &in) {
            in = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
        }

        ~Addrinfo() {
            freeaddrinfo(result);
        }
};

__attribute__((always_inline))
void init_resparser(const u_char *buffer, int size, ns_msg &handle, u_char **cp, ns_rr &rr, int &msg_count) {
    int ret = 0;
    if ((ret = ns_initparse(buffer, size, &handle)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }

    if ((ret = ns_parserr(&handle, ns_s_an, 0, &rr)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }

    msg_count = ns_msg_count(handle, ns_s_an);

    *cp = (u_char *)ns_rr_rdata(rr);
}

static
void parse_mx(const u_char *buffer, int size, string &record) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;

    if ((ret = ns_initparse(buffer, size, &handle)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }
    msg_count = ns_msg_count(handle, ns_s_an);


    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }
        cp = (u_char *)ns_rr_rdata(rr);

        record.append(to_string(i) + ".\n");
        // PREFERENCE
        record.append("\t" + to_string(ns_get16(cp)));

        // EXCHANGE
        cp += 2;
        if ((ret = ns_name_uncompress(ns_msg_base(handle), 
            ns_msg_end(handle), 
            cp, 
            dname, 
            sizeof(dname))) < 0) {
                STDERR(hstrerror(ret));
                throw exception();
        }
        record.append(" " + string(dname) + "\n");
    }
}

static
void parse_soa(const u_char *buffer, int size, string &record) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;

    init_resparser(buffer, size, handle, &cp, rr, msg_count);

    // MNAME
    if ((ret = ns_name_uncompress(ns_msg_base(handle), 
        ns_msg_end(handle), 
        cp, 
        dname, 
        sizeof(dname))) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
    }
    record.append("MNAME: " + string(dname) + "\n");

    cp += ret;

    // RNAME
    if ((ret = ns_name_uncompress(ns_msg_base(handle), 
        ns_msg_end(handle), 
        cp, 
        dname, 
        sizeof(dname))) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
    }
    record.append("RNAME: " + string(dname));
}

static
string dns2str(ns_type type, const u_char *buffer, int size) { 
    static unordered_map<unsigned, function<void(const u_char *buffer, int size, string &record)>> nsTypeParse {
        { ns_t_soa, parse_soa },
        { ns_t_mx, parse_mx }
    };
    auto it = nsTypeParse.find(type);
    string record;
    if (it == nsTypeParse.end()) {
        record.append("N/A");
        return record;
    }

    it->second(buffer, size, record);
    return record;
}

static
string query(const char *name, ns_type type, struct in_addr dns) {
    struct __res_state res;
    res_9_sockaddr_union u[1];
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    string record;

    memset(u, 0, sizeof(u));
    memset(&res, 0, sizeof(struct __res_state));

    if ((ret = res_ninit(&res)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }
    res.nscount = 0;

    #ifdef DEBUG
    res.options |= RES_DEBUG;
    #endif

    u[0].sin.sin_addr = dns;
    u[0].sin.sin_family = AF_INET;  // TODO: IPv6 support
    u[0].sin.sin_port = htons(53);

    res_setservers((res_state) &res, u, 1);
    
    if ((ret = res_nquery(&res, name, ns_c_in, type, buf, sizeof(buf))) > 0) {
        record.append(dns2str(type, buf, ret));
    }

    res_ndestroy(&res);
    return record;
}

int main(int argc, const char *argv[]) {

    STDOUT("Trying " << argv[1] << "...\n");
    vector<future<string>> queries;

    try {
        Addrinfo host(argv[1]);
        Addrinfo dns(argv[2]);

        struct in_addr in;
        dns.get_in4addr(in);

        queries.push_back(async(launch::async, [&]() { return query(host.name(), ns_t_aaaa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(host.name(), ns_t_a, in); }));
        queries.push_back(async(launch::async, [&]() { return query(host.name(), ns_t_soa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(host.name(), ns_t_mx, in); }));

        for (auto &q : queries) {
            STDOUT(q.get());
        }
        
    }
    catch(...) {
         exit(EXIT_FAILURE);
    }


    return EXIT_SUCCESS;
}

//TODO: konverze hostname na IP
