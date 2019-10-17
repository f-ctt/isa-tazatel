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
        ~A(){};
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
            return records; // FIXME: TODO: figure out what to do next
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
vector<RRNode> query(string hname, QTYPE qt, unsigned ttl) {
    struct __res_state resstate;
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    vector<unique_ptr<ResourceRecord>> records; 
    vector<future<vector<RRNode>>> responses;
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
                hname.c_str(), 
                ns_c_in,
                qt, 
                buf, 
                sizeof(buf))) > 0) {    // FIXME: not a desired behaviour (e.g. SOA)
        //records = dns2str(qt, buf, ret); // FIXME: NOTE: we assume the right answer
        records = parsedns_test(buf, ret, ns_s_an, qt); // FIXME: NOTE: we assume the right answer
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
                if (new_q.empty()) {
                    #ifdef DEBUG // FIXME: throw an exception. This may not happen
                    STDERR("WARNING: " << to_string(rrnode.record->qtype()) << " is empty!");
                    #endif
                    break;
                }
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
    res_nclose(&resstate);
    return root;
}

int main(int, const char *argv[]) {

    STDOUT("Trying " << argv[1] << "...\n");
    vector<future<vector<RRNode>>> responses;
    vector<RRNode> results;
    unsigned ttl = 3; // the level of recursion

    struct in6_addr host_in6;
    struct in_addr host_in;

    int is_host_in6 = inet_pton(AF_INET6, argv[1], &host_in6);
    int is_host_in = inet_pton(AF_INET, argv[1], &host_in);

    // TODO: support for cusotm DNS
    /* struct in_addr in;
    if (inet_pton(AF_INET, argv[2], &in) != 1) {
        exit(EXIT_FAILURE);
    }
 */
    try {
        if (is_host_in == 1) {  
            A ahost = A(host_in);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));   // AAAA(s)
        } else if (is_host_in6 == 1) {
            AAAA ahost = AAAA(host_in6);
            auto arpa = ahost.asQuery();
            responses.push_back(async(launch::async, [ttl, s = move(arpa)]() { return query(s, QTYPE::ptr, ttl); }));   // AAAA(s)
        } else {
            string t_aaaa(argv[1]);
            string t_a(argv[1]); 
            string t_mx(argv[1]);
            string t_soa(argv[1]);

            responses.push_back(async(launch::async, [ttl, s = move(t_aaaa)]() { return query(s, QTYPE::aaaa, ttl); }));   // AAAA(s)
            responses.push_back(async(launch::async, [ttl, s = move(t_a)]() { return query(s,QTYPE::a, ttl); }));   // AAAA(s)
            responses.push_back(async(launch::async, [ttl, s = move(t_mx)]() { return query(s, QTYPE::mx, ttl); }));   // AAAA(s)
            responses.push_back(async(launch::async, [ttl, s = move(t_soa)]() { return query(s, QTYPE::soa, ttl); }));   // AAAA(s)
        }
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
