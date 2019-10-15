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
#include <mutex>

using namespace std;

static mutex STDOUT_MX;
static mutex STDERR_MX;

#define STDERR(x) do { STDERR_MX.lock();cerr << __func__ << ":" <<__LINE__ << ": " << x << endl; STDERR_MX.unlock(); } while (0)
#define STDOUT(x) do { STDOUT_MX.lock(); cout << x << endl; STDOUT_MX.unlock(); } while (0)

enum QTYPE {
    a = 1,      // An A record for the domain name
    ns = 2, 	// A NS record( for the domain name
    cname = 5, 	// A CNAME record for the domain name
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
};

struct RRNode {
    unique_ptr<ResourceRecord> record; 
    vector<struct RRNode> children;
    void printTree() {
        for (auto &child : children)
            child.printTree();
        cout << record->toString() << endl;
    }
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
        string toString() { return string(name); };
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
};

class A : public ResourceRecord {
    private:
        struct in_addr addr;
    public:
        A(struct in_addr addr) : addr(addr) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>{ QTYPE::ptr }; }

        unsigned qtype() const { return QTYPE::a; } 

        string toString() {
            char buf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == NULL)
                throw runtime_error("inet_ntop zhorel a nemel");
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

class AAAA : public ResourceRecord {
    private:
        struct in6_addr addr;
    public:
        AAAA(struct in6_addr addr) : addr(addr) {}

        vector<QTYPE> asQueryTo() { return vector<QTYPE>{ QTYPE::ptr }; }

        unsigned qtype() const { return QTYPE::aaaa; }

        string toString() {
            char buf[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf)) == NULL)
                throw runtime_error("inet_ntop zhorel a nemel");
            return string(buf);
        }

        string asQuery() {
            struct in6_addr tmp = addr;
            for (auto &v : tmp.__in6_u.__u6_addr16) { //FIXME: I highly doubt this is fine
                v = htons(v);
            }
            string dname = this->toString();
            addr = tmp;
            return dname.append(".ip6.arpa"); 
        }
};

/* class NSParser {
    private:
        vector<u_char> rdata;
        __ns_sect section;
        ns_msg handle;
        int msg_count;
    public:
        NSParser(const u_char *rdata, int size, __ns_sect section) : rdata(rdata, rdata + size), section(section) {
            int ret = 0;
            if ((ret = ns_initparse(this->rdata.data(), size, &handle)) < 0)
                throw runtime_error(hstrerror(ret));
            msg_count = ns_msg_count(handle, section);
        }

        vector<ResourceRecord> parse(DNSResponse response) {
            ns_rr rr;
            int ret = 0;
            vector<ResourceRecord> rrecords;

            for (int i = 0; i < msg_count; ++i) {
                if ((ret = ns_parserr(&handle, section, rdata.size(), &rr)) < 0)
                    throw runtime_error(hstrerror(ret));
                for (auto c : response.components) {
                    switch(c) {
                        case RRComponent::DomainName:
                            break;
                        case RRComponent::IPv4:
                            break;
                        case RRComponent::IPv6:
                            break;
                        case RRComponent::u16:
                            break;
                        case RRComponent::u32:
                            break;
                        default:
                            throw runtime_error(string("NSParser::parse wrong component num: ") + 
                                to_string(c));
                    }
                }
            }
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
vector<unique_ptr<ResourceRecord>> parse_mx(const u_char *buffer, int size) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;

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
        uint16_t pref = ns_get16(cp);
        cp += 2;
        if ((ret = ns_name_uncompress(ns_msg_base(handle), 
            ns_msg_end(handle), 
            cp, 
            dname, 
            sizeof(dname))) < 0) {
                STDERR(hstrerror(ret));
                throw exception();
        }
        records.push_back(make_unique<MX>(MX(pref, dname)));
    }
    return records;
}

static
vector<unique_ptr<ResourceRecord>>parse_a(const u_char *buffer, int size) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;

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
        struct in_addr addr;
        memcpy(&addr, cp, sizeof(addr));
        records.push_back(make_unique<A>(A(addr)));
    }
    return records;
}

static
vector<unique_ptr<ResourceRecord>> parse_aaaa(const u_char *buffer, int size) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;

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
        struct in6_addr addr;
        memcpy(&addr, cp, sizeof(addr));
        records.push_back(make_unique<AAAA>(AAAA(addr)));
    }
    return records;
}

static
vector<unique_ptr<ResourceRecord>> parse_ptr(const u_char *buffer, int size) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;

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
        if ((ret = ns_name_uncompress(
            ns_msg_base(handle), 
            ns_msg_end(handle), 
            cp, 
            dname, 
            sizeof(dname))) < 0) {
                STDERR(hstrerror(ret));
                throw exception();
        }
        records.push_back(make_unique<PTR>(PTR(dname)));
    }
    return records;
}

static // TODO: if SOA not present, parse auth section
vector<unique_ptr<ResourceRecord>> parse_soa(const u_char *buffer, int size) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;
    vector<unique_ptr<ResourceRecord>> records;

    init_resparser(buffer, size, handle, &cp, rr, msg_count);
    if ((ret = ns_name_uncompress(ns_msg_base(handle), 
                                ns_msg_end(handle), 
                                cp, 
                                dname, 
                                sizeof(dname))) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
    }
    string mname(dname);
    cp += ret;
    if ((ret = ns_name_uncompress(ns_msg_base(handle), 
        ns_msg_end(handle), 
        cp, 
        dname, 
        sizeof(dname))) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
    }
    string rname(dname);
    records.push_back(make_unique<SOA>(SOA(mname, rname)));
    return records;
}

static
vector<unique_ptr<ResourceRecord>> dns2str(unsigned type, const u_char *buffer, int size) { 
    static unordered_map<unsigned, function<vector<unique_ptr<ResourceRecord>>(const u_char *buffer, int size)>> nsTypeParse {
        { ns_t_soa, parse_soa },
        { ns_t_mx, parse_mx },
        { ns_t_aaaa, parse_aaaa },
        { ns_t_a, parse_a },
        { ns_t_ptr, parse_ptr }
    };
    vector<unique_ptr<ResourceRecord>> records;
    auto it = nsTypeParse.find(type);
    if (it == nsTypeParse.end()) {
        return records;
    }

    return it->second(buffer, size);
}


static
vector<RRNode> query_test(string query, QTYPE qt, unsigned ttl) {
    struct __res_state resstate;
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    vector<unique_ptr<ResourceRecord>> records; 
    vector<RRNode> root;

    memset(&resstate, 0, sizeof(struct __res_state));
    if ((ret = res_ninit(&resstate)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }

    #ifdef DEBUG
    resstate.options |= RES_DEBUG; // FIXME: not working under Linux????
    #endif
    
    if ((ret = res_nquery(&resstate, 
                query.c_str(), 
                ns_c_in,
                qt, 
                buf, 
                sizeof(buf))) > 0) {    // FIXME: not a desired behaviour (e.g. SOA)
        records = dns2str(qt, buf, ret);
    } 
    #ifdef DEBUG
    else 
        STDERR(hstrerror(h_errno) << ", " << qt << " " << query << " " << ttl);
    #endif
    vector<future<vector<RRNode>>> responses;
    while (!records.empty()) {
        root.push_back(RRNode { move(records.back()) });
        records.pop_back();
    }
    if (ttl > 0) {
        for (auto &rrnode : root) {
            for (auto qtype : rrnode.record->asQueryTo()) {
                auto new_q = rrnode.record->asQuery();
                if (new_q.empty()) {
                    #ifdef DEBUG
                    STDERR("WARNING: " << to_string(rrnode.record->qtype()) << " is empty!");
                    #endif
                    break;
                }
                //auto result = query_test(move(new_q), qtype);
                responses.push_back(async(launch::async, 
                    [ttl, qtype, s = move(new_q)](){ return query_test(s, qtype, ttl - 1); }));
            }
        }
    }
    size_t idx_max = (responses.size() > root.size() ? root.size() : responses.size());
    for (size_t i = 0; i < idx_max; ++i) {
        auto res_val = responses[i].get();
        root[i].children.reserve(res_val.size());
        root[i].children.insert(root[i].children.end(), 
            make_move_iterator(res_val.begin()), 
            make_move_iterator(res_val.end()));
    }
    res_nclose(&resstate);
    return root;
}

/* static
string query(const char *name, ns_type type, struct in_addr dns) {
    struct __res_state res;
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    string record;

    memset(&res, 0, sizeof(struct __res_state));

    if ((ret = res_ninit(&res)) < 0) {
        STDERR(hstrerror(ret));
        throw exception();
    }
    res.nscount = 0;

    #ifdef DEBUG
    res.options |= RES_DEBUG;
    #endif

    #ifdef __APPLE__
    res_9_sockaddr_union u[1];
    memset(u, 0, sizeof(u));
    u[0].sin.sin_addr = dns;
    u[0].sin.sin_family = AF_INET;  // TODO: IPv6 support
    u[0].sin.sin_port = htons(53);
    res_setservers((res_state) &res, u, 1);
    #else
    // TODO: write your own impl of set_server
    // use externet set_servers
    #endif

    if ((ret = res_nquery(&res, name, ns_c_in, type, buf, sizeof(buf))) > 0) {
        //record.append(dns2str(type, buf, ret));
    }
    #ifdef __APPLE__
    res_ndestroy(&res);
    #else
    res_nclose(&res);
    #endif

    return record;
} */

int main(int argc, const char *argv[]) {

    STDOUT("Trying " << argv[1] << "...\n");
    vector<future<vector<RRNode>>> responses;
    vector<RRNode> results;
    unsigned ttl = 3; // the level of recursion

    try {
        struct in_addr in;
        if (inet_pton(AF_INET, argv[2], &in) != 1) {
            exit(EXIT_FAILURE);
        }
        // TODO: PTR if dname is IP
        string t_aaaa(argv[1]);
        string t_a(argv[1]); 
        string t_mx(argv[1]);
        string t_soa(argv[1]);

        responses.push_back(async(launch::async, [ttl, s = move(t_aaaa)]() { return query_test(s, QTYPE::aaaa, ttl); }));   // AAAA(s)
        responses.push_back(async(launch::async, [ttl, s = move(t_a)]() { return query_test(s,QTYPE::a, ttl); }));   // AAAA(s)
        responses.push_back(async(launch::async, [ttl, s = move(t_mx)]() { return query_test(s, QTYPE::mx, ttl); }));   // AAAA(s)
        responses.push_back(async(launch::async, [ttl, s = move(t_soa)]() { return query_test(s, QTYPE::soa, ttl); }));   // AAAA(s)

        // TODO: refactor
        for (auto &r : responses) {
            auto res_value = r.get();
            results.insert(results.end(),
                make_move_iterator(res_value.begin()),
                make_move_iterator(res_value.end()));
        }

        STDOUT("========= DNS =========\n");

        for (auto &result : results)
            result.printTree();
    }
    catch(...) {
         exit(EXIT_FAILURE);
    }


    return EXIT_SUCCESS;
}

//  TODO: debug __LINE__ msgs
