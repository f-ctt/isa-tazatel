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

static sockaddr_storage DNS_SADDR;
static int TAR_AFINET_DNS = 0;

enum QTYPE {
    a = 1,      // An A record for the domain name
    ns = 2, 	// A NS record( for the domain name
    cname = 5, 	// A CNAME record for the domain name
    soa = 6, 	// A SOA record for the domain name
    ptr = 12, 	// A PTR record(s) for the domain name
    mx = 15, 	// A MX record for the domain name
    aaaa = 28 	// An AAAA record(s) for the domain name
};

class Record {
    public:
        virtual const char *descr() const = 0;
        virtual string toString() = 0;
        virtual string asQuery() = 0;
        virtual unsigned qtype() const = 0;
        virtual vector<QTYPE> asQueryTo() = 0;
        virtual ~Record() {};
};

using RecordPtr = unique_ptr<Record>;
using Records = vector<RecordPtr>;

struct RecordNode {
    RecordPtr record; 
    vector<struct RecordNode> children;
    void printTree(const string &prefix, bool last) {
        cout << prefix << (last ? "└──" : "├──");
        auto desc = record->descr();
        cout << desc;
        for (size_t i = 0; i < 6 - strlen(desc); ++i)
            cout << "─";
        cout << record->toString() << endl;
        unsigned cnt = 0;
        for (auto &ch : children) {
            cnt++;
            bool lst = (cnt == children.size());
            ch.printTree(prefix + (last ? "         " : "|         "), lst);
        }
    }
};

using RecordNodes = vector<RecordNode>;

class Whois : public Record {
    private:
        string answer;
    public:
        Whois(string answer) : answer(answer) {}
        const char *descr() const { return "WHOIS"; }
        string toString() { return answer; }
        string asQuery()  { return string(); }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }
        unsigned qtype() const { return 0; }
};

class MX : public Record {
    private:
        uint16_t pref;
        string exch;
    public:
        MX(uint16_t pref, string exch) : pref(pref), exch(exch) {}
        const char *descr() const { return "MX"; }
        string asQuery() { return string(); }
        string toString() { return string(to_string(pref).append(" ") + exch); }
        unsigned qtype() const { return QTYPE::mx; }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }
        ~MX(){ }
};

class CNAME: public Record {
    private:
        string cname;
    public:
        CNAME(string cname) : cname(cname) {}
        const char *descr() const { return "CNAME"; }
        string asQuery() { return cname; }
        unsigned qtype() const { return QTYPE::cname; }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); } // TODO: unimplemented
        string toString() { return cname; }
};

class PTR : public Record {
    private:
        string name;
    public:
        PTR(string name) : name(name) {}
        const char *descr() const { return "PTR"; }
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
};

class SOA : public Record {
    private:
        string mname;
        string rname;
    public:
        SOA(string mname, string rname) : mname(mname), rname(rname) {}
        const char *descr() const { return "SOA"; }
        vector<QTYPE> asQueryTo() { return vector<QTYPE>(); }

        unsigned qtype() const { return QTYPE::soa; }

        string asQuery() { return string(); } 

        string toString() {
            return string(mname.append(" ").append(rname));
        }
        ~SOA(){};
};

class A : public Record {
    private:
        struct in_addr addr;
    public:
        A(struct in_addr addr) : addr(addr) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>{ QTYPE::ptr }; }

        const char *descr() const { return "A"; }
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
};

class NS: public Record {
        private:
            string name;
        public:
            NS(string name) : name(name) {}
            vector<QTYPE> asQueryTo() { return vector<QTYPE>(); } // TODO: unimplemented
            unsigned qtype() const { return QTYPE::ns; }
            string toString() { return name; }
            string asQuery() { return name; }
            const char *descr() const { return "NS"; }
};

class AAAA : public Record {
    private:
        struct in6_addr addr;
    public:
        AAAA(struct in6_addr addr) : addr(addr) {}
        const char *descr() const { return "AAAA"; }

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
};

static
vector<unique_ptr<Record>> 
parsedns(const u_char *rdata, int size, __ns_sect section, unsigned tarqtype) {
    char dname[NS_MAXDNAME] = {0};
    int ret = 0;
    ns_msg handle;
    ns_rr rr;
    u_char *cp = NULL;
    unsigned actual_qtype = 0;
    int msg_count = 0;
    vector<unique_ptr<Record>> records;
    if ((ret = ns_initparse(rdata, size, &handle)) < 0)
        throw runtime_error(string() + "initparse: " + hstrerror(ret));
    msg_count = ns_msg_count(handle, section); // TODO: support for auth section in case SOA is not in the an section
    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, section, i, &rr)) < 0)
            throw runtime_error(string() + "parserr: " + hstrerror(ret));
        if ((actual_qtype = ns_rr_type(rr)) != tarqtype)
            continue; // NOTE: skipping an answer we didn't ask for
        cp = (u_char *)ns_rr_rdata(rr);
        switch(actual_qtype) {
            case ns_t_a: {
                struct in_addr addr;
                memcpy(&addr, cp, sizeof(addr));
                records.push_back(make_unique<A>(A(addr)));
            } break;
            case ns_t_ns: {
                if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                            ns_msg_end(handle), 
                            cp, 
                            dname, 
                            sizeof(dname))) < 0) {
                    STDERR(hstrerror(ret));
                    throw runtime_error("NS parsing failed");
                }
                records.push_back(make_unique<NS>(NS(dname)));
            }break;
            case ns_t_cname: {
                if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                            ns_msg_end(handle), 
                            cp, 
                            dname, 
                            sizeof(dname))) < 0) {
                    STDERR(hstrerror(ret));
                    throw runtime_error("CNAME parsing failed");
                }
                records.push_back(make_unique<CNAME>(CNAME(dname)));
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
                    throw runtime_error("SOA parsing failed");
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
                #ifdef DEBUG
                    STDERR("WARNING: Qtype not handled: " << actual_qtype);
                #endif
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
        state->nsaddr_list[0].sin_addr = ((sockaddr_in *)&DNS_SADDR)->sin_addr;
        state->_u._ext.nsaddrs[0] = NULL;
    } else if (af == AF_INET6) {
        state->nsaddr_list[0].sin_family = 0;
        sockaddr_in6 *sin6 = (sockaddr_in6 *) malloc(sizeof(sockaddr_in6));
        memset(sin6, 0, sizeof(sockaddr_in));
        sin6->sin6_scope_id = 0;
        sin6->sin6_addr = ((sockaddr_in6 *)&DNS_SADDR)->sin6_addr;
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

static
vector<RecordNode> query(string hname, QTYPE qt, unsigned ttl) {
    struct __res_state resstate;
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    vector<unique_ptr<Record>> records; 
    vector<future<vector<RecordNode>>> responses;
    vector<RecordNode> root;

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
                sizeof(buf))) > 0) {  
        records = parsedns(buf, ret, ns_s_an, qt);
    } else if (qt == QTYPE::soa && buf[9]) { // Test if there is an msg in authoritative section
        // res_nquery returns -1, need to get the total len manually
        int cnt = 512;
        while (buf[--cnt] == '\0' && cnt > 0); 
        STDOUT("size: " << cnt);
        records = parsedns(buf, cnt + 1, ns_s_ns, qt); // cnt + 1 -> idx + 1 to get the total len
    }
    #ifdef DEBUG
        else {
            STDERR(hstrerror(h_errno) << ", " << qt << " " << hname << " " << ttl);
        }
    #endif
    while (!records.empty()) {
        root.push_back(RecordNode { move(records.back()) });
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
    auto response = query(whost, QTYPE::a, 0);
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

static
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
            throw runtime_error(string() + "whost: " + hstrerror(h_errno));
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

static
void set_dns(char *dnsip) {
    if (inet_pton(AF_INET, dnsip, &((sockaddr_in *)&DNS_SADDR)->sin_addr) != 1) {
        if (inet_pton(AF_INET6, dnsip, &((sockaddr_in6 *)&DNS_SADDR)->sin6_addr) != 1) {
            print_help();
            exit(EXIT_FAILURE);
        }
        TAR_AFINET_DNS = AF_INET6;
        return;
    } 
    TAR_AFINET_DNS = AF_INET;
}

int main(int argc, char *const *argv) {
    vector<future<vector<RecordNode>>> responses;
    future<string> whois_res;
    vector<RecordNode> results;
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
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));
            auto str = ahost.toString();
            whois_res = async(launch::async, [str, w]() { return whois_nquery(str, w); });
        } else if (inet_pton(AF_INET6, q, &((sockaddr_in6 *)&in)->sin6_addr) == 1) {
            AAAA ahost = AAAA(((sockaddr_in6 *)&in)->sin6_addr);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));
            auto str = ahost.toString();
            whois_res = async(launch::async, [str, w]() { return whois_nquery(str, w); });
        } else {
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::soa, ttl); }));
            auto ares = async(launch::async, [ttl, q]() { return query(q, QTYPE::a, ttl); }); 
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::aaaa, ttl); }));
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::mx, ttl); })); 
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::ns, ttl); }));
            responses.push_back(async(launch::async, [ttl, q]() { return query(q, QTYPE::cname, ttl); }));
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

    // TODO: 
    // 
    cout << q << endl;
    unsigned cnt = 0;
    for (auto &result : results) {
        cnt++;
        bool last = (cnt == results.size());
        result.printTree("    ", last);
    }

    cout <<"\n========= WHOIS =========\n\n";
    if (whois_res.valid())
        cout << whois_res.get() << endl;

    return EXIT_SUCCESS;
}