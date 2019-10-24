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
#include <cstring>
#include <functional>
#include <unistd.h>
#include <mutex>
#include <getopt.h>
#include <sstream>

using namespace std;

static mutex STDOUT_MX;
static mutex STDERR_MX;


#define STDERR(x) do { STDERR_MX.lock();cerr << __func__ << ":" <<__LINE__ << ": " << x << endl; STDERR_MX.unlock(); } while (0)
#define STDOUT(x) do { STDOUT_MX.lock(); cout << x << endl; STDOUT_MX.unlock(); } while (0)

static struct sockaddr_in WHOST;
static struct in6_addr DNS_IN6;
static struct in_addr DNS_IN;
static int TAR_AFINET_DNS = 0;

enum QTYPE {
    a = 1,      // An A record for the domain name
    //ns = 2, 	// A NS record( for the domain name
    //cname = 5, 	// A CNAME record for the domain name
    soa = 6, 	// A SOA record for the domain name
    ptr = 12, 	// A PTR record(s) for the domain name
    mx = 15, 	// A MX record for the domain name
    aaaa = 28 	// An AAAA record(s) for the domain name
};

class ResourceRecord {
    public:
        virtual string toString() = 0;
        virtual string asQuery() = 0;
        virtual unsigned qtype() const = 0;
        virtual vector<QTYPE> asQueryTo() = 0;
        virtual ~ResourceRecord() {};
};

struct RRNode {
    unique_ptr<ResourceRecord> record; 
    vector<struct RRNode> children;
    void printTree(unsigned depth = 0) {
        for (auto &child : children)
            child.printTree(depth + 1);
        while (depth-- > 0)
            cout << "\t\t";
        cout << record->toString() << endl;
    }
};

class Query {
    //virtual ~Query() = 0;
    //virtual vector<ResourceRecord> send() = 0;
};

class DNSQuery : Query {

};

class WhoisQuery : Query {

};

// FIXME: TODO: this is wrongly named as whois answers maay contain DNS resource records
// also qtype doesn't fit here
// basically a bullshit abstraction
class Whois : public ResourceRecord {
    private:
        string answer;
    public:
        Whois(string answer) : answer(answer) {}
        string toString() { return answer; }
        string asQuery()  { return string(); }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }
        unsigned qtype() const { return 0; }
};

class MX : public ResourceRecord {
    private:
        uint16_t pref;
        string exch;
    public:
        MX(uint16_t pref, string exch) : pref(pref), exch(exch) {}
        string asQuery() { return string(); }
        string toString() { return string(to_string(pref).append(" ") + exch); }
        unsigned qtype() const { return QTYPE::mx; }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }
        ~MX(){ }
};

class PTR : public ResourceRecord {
    private:
        string name;
    public:
        PTR(string name) : name(name) {}
        string asQuery() { return this->toString(); } 
        unsigned qtype() const { return QTYPE::ptr; }
        vector<QTYPE> asQueryTo() { 
            return vector<QTYPE>
                {
                    QTYPE::a,
                    QTYPE::aaaa,
                    QTYPE::mx,
                    QTYPE::soa
                }; 
        }
        string toString() { return name; };
        ~PTR() {};
};

class SOA : public ResourceRecord {
    private:
        string mname;
        string rname;
    public:
        SOA(string mname, string rname) : mname(mname), rname(rname) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }

        unsigned qtype() const { return QTYPE::soa; }

        string asQuery() { return string(); } 

        string toString() {
            return string(mname.append(" ").append(rname));
        }
        ~SOA(){};
};

class A : public ResourceRecord {
    private:
        struct in_addr addr;
    public:
        A(struct in_addr addr) : addr(addr) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>{ QTYPE::ptr }; }

        unsigned qtype() const { return QTYPE::a; } 

        struct in_addr inaddr() { return addr; }

        string toString() {
            char buf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == NULL)
                throw runtime_error("inet_ntop zhorel a nemel v A");
            return string(buf);
        }
        string asQuery() {
            struct in_addr tmp = addr;
            addr.s_addr = htonl(addr.s_addr);
            auto dname = this->toString();
            addr = tmp;
            return dname.append(".in-addr.arpa");
        }
        ~A(){};
};

class AAAA : public ResourceRecord {
    private:
        struct in6_addr addr;
    public:
        AAAA(struct in6_addr addr) : addr(addr) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>{ QTYPE::ptr }; }

        unsigned qtype() const { return QTYPE::aaaa; }

        struct in6_addr in6addr() { return addr; }

        string toString() {
            char buf[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf)) == NULL)
                throw runtime_error("inet_ntop zhorel v AAAA");
            return string(buf);
        }
        // e.g. "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
        // source: nslookup.c
        // FIXME: not really a protable code due to the inner members of 'addr'
        string asQuery() {
            char resbuf[80]= {0};
            const unsigned char v4_mapped[12] = { 0,0,0,0, 0,0,0,0, 0,0, 0xff, 0xff };
            if (memcmp(addr.__in6_u.__u6_addr8, v4_mapped, 12) != 0) {
                char hexdigits_upcase[] = "0123456789ABCDEF";
                int i;
                char *ptr = resbuf;
                for (i = 0; i < 16; i++) {
                    *ptr++ = 0x20 | hexdigits_upcase[(unsigned char)addr.__in6_u.__u6_addr8[15 - i] & 0xf];
                    *ptr++ = '.';
                    *ptr++ = 0x20 | hexdigits_upcase[(unsigned char)addr.__in6_u.__u6_addr8[15 - i] >> 4];
                    *ptr++ = '.';
                }
                strcpy(ptr, "ip6.arpa");
                return string(resbuf);
            }
            snprintf(resbuf, sizeof(resbuf), "%u.%u.%u.%u.in-addr.arpa",
                    addr.__in6_u.__u6_addr8[15], 
                    addr.__in6_u.__u6_addr8[14], 
                    addr.__in6_u.__u6_addr8[13], 
                    addr.__in6_u.__u6_addr8[12]);
            return string(resbuf);
        }
        ~AAAA(){};
};

static
vector<unique_ptr<ResourceRecord>> 
parsedns_test(const u_char *rdata, int size, __ns_sect section, unsigned tarqtype) {
    char dname[NS_MAXDNAME] = {0};
    int ret = 0;
    ns_msg handle;
    ns_rr rr;
    u_char *cp = NULL;
    unsigned actual_qtype = 0;
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;
    if ((ret = ns_initparse(rdata, size, &handle)) < 0)
        throw runtime_error(hstrerror(ret));
    msg_count = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, section, i, &rr)) < 0)
            throw runtime_error(hstrerror(ret));
        if ((actual_qtype = ns_rr_type(rr)) != tarqtype)
            continue; // FIXME: TODO: figure out what to do next
        cp = (u_char *)ns_rr_rdata(rr);
        switch(actual_qtype) {
            case ns_t_a: {
                struct in_addr addr;
                memcpy(&addr, cp, sizeof(addr));
                records.push_back(make_unique<A>(A(addr)));
            } break;
            case ns_t_aaaa: {
                struct in6_addr addr6in;
                memcpy(&addr6in, cp, sizeof(addr6in));
                records.push_back(make_unique<AAAA>(AAAA(addr6in)));
            } break;
            case ns_t_soa: {
                if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                                    ns_msg_end(handle), 
                                    cp, 
                                    dname, 
                                    sizeof(dname))) < 0) {
                        STDERR(hstrerror(ret));
                        throw runtime_error("Soa parsing failed");
                }
                string mname(dname);
                cp += ret;
                if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                    ns_msg_end(handle), 
                    cp, 
                    dname, 
                    sizeof(dname))) < 0) {
                        STDERR(hstrerror(ret));
                        throw runtime_error("Soa parsing failed");
                }
                string rname(dname);
                records.push_back(make_unique<SOA>(SOA(mname, rname)));
            } break;
            case ns_t_mx: {
                uint16_t pref = ns_get16(cp);
                cp += 2;
                if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                    ns_msg_end(handle), 
                    cp, 
                    dname, 
                    sizeof(dname))) < 0) {
                        STDERR(hstrerror(ret));
                        throw runtime_error("MX parsing failed");
                }
                records.push_back(make_unique<MX>(MX(pref, dname)));
            } break;
            case ns_t_ptr: 
                if ((ret = ns_name_uncompress(
                            ns_msg_base(handle), 
                            ns_msg_end(handle), 
                            cp, 
                            dname, 
                            sizeof(dname))) < 0) {
                                STDERR(hstrerror(ret));
                                throw runtime_error("PTR parsing failed");
                        }
                records.push_back(make_unique<PTR>(PTR(dname)));
                break;
            default:
                throw runtime_error("qtype not handled");
                break;
        }
    }
    return records;
}
static
void res_ndestroy(res_state state) {
    res_nclose(state);
    for (int i = 0; i < 3; ++i) {
        if (state->_u._ext.nsaddrs[i] != NULL) {
            free(state->_u._ext.nsaddrs[i]);
            state->_u._ext.nsaddrs[i] = NULL;
        }
    }
    state->options &= ~RES_INIT;
}

static
int res_setserver(res_state state, int af) {
    if (af == AF_INET) {
        state->nsaddr_list[0].sin_family = af;
        state->nsaddr_list[0].sin_port = htons(53);
        state->nsaddr_list[0].sin_addr = DNS_IN;
        state->_u._ext.nsaddrs[0] = NULL;

    } else if (af == AF_INET6) {
        state->nsaddr_list[0].sin_family = 0;
        sockaddr_in6 *sin6 = (sockaddr_in6 *) malloc(sizeof(sockaddr_in6));
        memset(sin6, 0, sizeof(sockaddr_in));
        sin6->sin6_scope_id = 0;
        sin6->sin6_addr = DNS_IN6;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(53);
        state->_u._ext.nsaddrs[0] = sin6;
    } else {
        return -1;
    }
    state->nscount = 1;
    return 0;
}

__attribute__((__always_inline__))
static
void erase_all(string &str, const string &chars = "\n\r\n \\") {
    for (auto ch: chars)
        str.erase(std::remove(str.begin(), str.end(), ch), str.end());
}

/**
 * @brief Sends whois query('ip') to whois server('addr') and saves the answer in 'response'
 * 
 * @param in whois server addr
 * @param ip The addr of the host
 * @param af AF_INET/AF_INET6
 * @param buf buffer for a response. If a return value equals to -2, this buffer 
 *          contains hostname of the next whost that the former points to
 * @return int 0 if success, -1 on failure, -2 if the current whost points to 
 *          another whost - redireciton
 */
static
int whois_nquery(const char *ip, int af, string &response) {
    int ret, sock, rsize = sock = ret = 0;
    char buf[1500] = {0}; // ethernet's datagram size

    if ((sock = socket(af, SOCK_STREAM, IPPROTO_TCP)) == -1) { // socket sets errno
        return -1;
    }
	if (connect(sock , (sockaddr *)&WHOST, sizeof(WHOST))) {// connect sets errno
        return -1;
    }
    
    string wquery = string() + ip + "\r\n";
	if (send(sock, wquery.c_str(), wquery.size(), 0) < 0) // sets errno as well
        return -1;
    while ((rsize = recv(sock, buf, sizeof(buf), 0)) > 0) {
        size_t pos = string::npos;
        istringstream stream(buf);
        for (string line; getline(stream, line); ) {
            transform(line.begin(), line.end(), line.begin(),
                [](unsigned char c){ return tolower(c); });
            if ((pos = line.find("whois:")) != string::npos) {
                erase_all(line);
                response = line.substr(pos + strlen("whois:"), line.size());
                close(sock);
                return -2;
            }
            else if ((pos = line.find("whois server:")) != string::npos) {
                erase_all(line);
                response = line.substr(pos + strlen("whois server:"), line.size());
                close(sock);
                return -2;
            } 
        }
        response.insert(response.end(), buf, buf + rsize);
    }
    if (rsize < 0) {
        ret = -1;
    }
	close(sock);
	return ret;
}

static
vector<RRNode> query(string hname, QTYPE qt, unsigned ttl) {
    struct __res_state resstate;
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    vector<unique_ptr<ResourceRecord>> records; 
    vector<future<vector<RRNode>>> responses;
    vector<RRNode> root;

    memset(&resstate, 0, sizeof(struct __res_state));
    if ((ret = res_ninit(&resstate)) < 0)
        throw runtime_error(hstrerror(ret));

    if (TAR_AFINET_DNS) {
        if (res_setserver(&resstate, TAR_AFINET_DNS))
            throw runtime_error("Setting DNS server failed");
    }
    #if defined(DEBUG) && defined(__APPLE__)
    // NOTE: It doesn't work in glibc (https://github.com/bminor/glibc/blob/master/resolv/README#L21) 
    // it only works if glibc was build with debug option
    resstate.options |= RES_DEBUG; 
    #endif
    
    if ((ret = res_nquery(&resstate, 
                hname.c_str(), 
                ns_c_in,
                qt, 
                buf, 
                sizeof(buf))) > 0) {    // FIXME: not a desired behaviour (e.g. SOA)
        records = parsedns_test(buf, ret, ns_s_an, qt);
    } 
    #ifdef DEBUG
    else 
        STDERR(hstrerror(h_errno) << ", " << qt << " " << hname << " " << ttl);
    #endif
    while (!records.empty()) {
        root.push_back(RRNode { move(records.back()) });
        records.pop_back();
    }
    if (ttl > 0) {
        for (auto &rrnode : root) {
            for (auto qtype : rrnode.record->asQueryTo()) {
                auto new_q = rrnode.record->asQuery();
                if (new_q.empty())
                    throw runtime_error(to_string(qtype) + " as query() returns empty string"); 
                responses.push_back(async(launch::async, 
                    [ttl, qtype, s = move(new_q)](){ return query(s, qtype, ttl - 1); }));
            }
        }
    }
    size_t tar_idx = 0;
    for (auto &node : root) {
        for (size_t i = 0; i < node.record->asQueryTo().size() && tar_idx < responses.size(); ++i) {
            auto res_val = responses[tar_idx++].get(); // NOTE: ++
            node.children.insert(node.children.end(),
            make_move_iterator(res_val.begin()),
            make_move_iterator(res_val.end()));
        }
    }
    res_ndestroy(&resstate);
    return root;
}

static
void print_help() {
    cout << "No help yet.." << endl;
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

static
void set_whost(const char *whost) {
    sockaddr_in whin;
    memset(&whin, 0, sizeof(whin));
    #ifdef DEBUG
    STDOUT("Setting up whost..." << \
        "\nAssuming whost format: hostname");
    #endif
    auto response = query(whost, QTYPE::a, 0); // assume user issued a hostname first
    if (response.empty()) {
        #ifdef DEBUG
        STDOUT("Fetching IP of " << whost << " failed.\
            \nAssuming whost format: IP. Trying to fetch hostname.");
        #endif
        response = query(whost, QTYPE::ptr, 0);
        if (response.empty())
            throw runtime_error("Couldn't reach " + string(whost));
        if (inet_pton(AF_INET, whost, &whin.sin_addr.s_addr) != 1)
            throw runtime_error("Inetrnal error");
    } else {
        // FIXME: assumption response.back() can be problematic in the future because of different
        // types of 1:N answer
        whin.sin_addr = dynamic_cast<A*>(response.back().record.get())->inaddr(); // ^_^
    }
    whin.sin_family = AF_INET;
    whin.sin_port = htons(43);
    WHOST = whin;
}
// TODO: REFACTOR: use one buffer for both addresses
static
void set_dns(char *dnsip) {
    if (inet_pton(AF_INET, dnsip, &DNS_IN) != 1) {
        if (inet_pton(AF_INET6, dnsip, &DNS_IN6) != 1) {
            print_help();
            exit(EXIT_FAILURE);
        }
        TAR_AFINET_DNS = AF_INET6;
        return;
    } 
    TAR_AFINET_DNS = AF_INET;
}

int main(int argc, char *const *argv) {
    vector<future<vector<RRNode>>> responses;
    vector<RRNode> results;
    string whois_ans;
    unsigned ttl = 1; // the level of recursion
    int ret = 0;
    char *q = NULL, *w = NULL, *d = NULL;

    check_argv(argc, argv, &q, &w, &d);

    struct in6_addr host_in6;
    struct in_addr host_in;

    int is_host_in6 = inet_pton(AF_INET6, q, &host_in6);
    int is_host_in = inet_pton(AF_INET, q, &host_in);

    if (d != NULL)
      set_dns(d);

    try {
        set_whost(w);
        if (is_host_in == 1) {  
            A ahost = A(host_in);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));
            auto str = ahost.toString();
            while ((ret = whois_nquery(str.c_str(), AF_INET, whois_ans)) == -2) {
                #ifdef DEBUG
                STDOUT("[Redirecting to " << whois_ans << "] ...");
                #endif
                set_whost(whois_ans.c_str());
            }
            if (ret == -1)
                throw runtime_error(string() + "whois query failed: " + strerror(ret));
        } else if (is_host_in6 == 1) {
            AAAA ahost = AAAA(host_in6);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));
            // TODO: whois support for IPv6
        } else {
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::aaaa, ttl); }));
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::a, ttl); })); 
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::mx, ttl); })); 
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::soa, ttl); }));
        }
        // TODO: refactor
        for (auto &r : responses) {
            auto res_value = r.get();
            results.insert(results.end(),
                make_move_iterator(res_value.begin()),
                make_move_iterator(res_value.end()));
        }

        cout << "\n========= DNS =========\n\n";

        for (auto &result : results)
            result.printTree();

        cout <<"\n========= WHOIS =========\n\n";
        cout << whois_ans << endl;
    }
    catch(const runtime_error &error) {
        STDERR(error.what());
        exit(EXIT_FAILURE);
    }


    return EXIT_SUCCESS;
}

//  TODO: debug __LINE__ msgs
