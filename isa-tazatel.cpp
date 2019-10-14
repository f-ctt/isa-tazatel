#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <thread>
#include <future>
#include <vector>
#include <tuple>
#include <cstring>
#include <unordered_map>
#include <functional>
#include <unistd.h>

using namespace std;

#define STDERR(x) do { cerr << __func__ << ":" <<__LINE__ << ": " << x << endl; } while (0)
#define STDOUT(x) do { cout << x << endl; } while (0)

struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct QUESTION
{
    u_int16_t qtype;
    u_int16_t qclass;
};

struct IntFields {
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlen;
} __attribute__((__packed__));
  
/* class Addrinfo {

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

        vector<string> aaaa2str() {
            struct addrinfo *next = result;
            vector<string> aaaas;

            while (next != NULL) {
                if(next->ai_family == AF_INET6) {
                    char buf[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6,
                        &((struct sockaddr_in6 *)next->ai_addr)->sin6_addr,
                        buf,
                        INET6_ADDRSTRLEN);
                    
                    aaaas.push_back(string(buf));
                }
            }
            return aaaas;
        }

        ~Addrinfo() {
            freeaddrinfo(result);
        }
}; */

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

    record.append("\nMX: ");
    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }
        cp = (u_char *)ns_rr_rdata(rr);

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
void parse_a(const u_char *buffer, int size, string &record) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char buf[INET_ADDRSTRLEN] = {0};
    int msg_count = 0;

    if ((ret = ns_initparse(buffer, size, &handle)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }
    msg_count = ns_msg_count(handle, ns_s_an);

    record.append("A: ");

    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }
        cp = (u_char *)ns_rr_rdata(rr);

        if (inet_ntop(AF_INET, cp, buf, sizeof(buf)) == NULL) {
            STDERR(strerror(errno));
            throw exception();
        }
        record.append("\t" + string(buf) + "\n");       
    }
}

static
void parse_aaaa(const u_char *buffer, int size, string &record) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char buf[INET6_ADDRSTRLEN] = {0};
    int msg_count = 0;

    if ((ret = ns_initparse(buffer, size, &handle)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }
    msg_count = ns_msg_count(handle, ns_s_an);

    record.append("AAAA: ");

    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }
        cp = (u_char *)ns_rr_rdata(rr);

        if (inet_ntop(AF_INET6, cp, buf, sizeof(buf)) == NULL) {
            STDERR(strerror(errno));
            throw exception();
        }
        record.append("\t" + string(buf) + "\n");       
    }
}

static
void parse_ptr(const u_char *buffer, int size, string &record) {
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

    record.append("PTR: ");

    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }

        cp = (u_char *)ns_rr_rdata(rr);

        if ((ret = ns_name_uncompress(
            ns_msg_base(handle), 
            ns_msg_end(handle), 
            cp, 
            dname, 
            sizeof(dname))) < 0) {
                STDERR(hstrerror(ret));
                throw exception();
        }
        record.append("\t" + string(dname) + "\n"); 
    }
}

static // TODO: if SOA not present, parse auth section
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
    record.append("MNAME:\t" + string(dname) + "\n\n");

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
    record.append("RNAME:\t" + string(dname));
}

static
string dns2str(ns_type type, const u_char *buffer, int size) { 
    static unordered_map<unsigned, function<void(const u_char *buffer, int size, string &record)>> nsTypeParse {
        { ns_t_soa, parse_soa },
        { ns_t_mx, parse_mx },
        { ns_t_aaaa, parse_aaaa },
        { ns_t_a, parse_a },
        { ns_t_ptr, parse_ptr }
    };
    auto it = nsTypeParse.find(type);
    string record;
    if (it == nsTypeParse.end()) {
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
        struct in_addr in;
        if (inet_pton(AF_INET, argv[2], &in) != 1) {
            exit(EXIT_FAILURE);
        }

        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_aaaa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_a, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_soa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_mx, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_ptr, in); }));

        STDOUT("========= DNS =========\n");

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
