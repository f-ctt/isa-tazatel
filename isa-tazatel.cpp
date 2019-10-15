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

enum QTYPE {
    a = 1,      // An A record for the domain name
    ns = 2, 	// A NS record( for the domain name
    cname = 5, 	// A CNAME record for the domain name
    soa = 6, 	// A SOA record for the domain name
    ptr = 12, 	// A PTR record(s) for the domain name
    mx = 15, 	// A MX record for the domain name
    aaaa = 28 	// An AAAA record(s) for the domain name
};

struct DNSQuery {
    string dname;
    unsigned qtype;
    int af;
    union {
        struct in6_addr in6;
        struct in_addr in;
    };
    DNSQuery(string dname, unsigned qtype, int af, struct in6_addr in6) :
        dname(dname), qtype(qtype), af(af), in6(in6) { }
    DNSQuery(string dname, unsigned qtype, int af, struct in_addr in) :
        dname(dname), qtype(qtype), af(af), in(in) { }
};


class ResourceRecord {
    public:
        virtual string toString() = 0;
        virtual unique_ptr<DNSQuery> asQuery() = 0;
        virtual unsigned qtype() const = 0;
        virtual vector<QTYPE> asQueryTo() = 0;
};

class PTR : public ResourceRecord {
    private:
        string name;
    public:
        PTR(string name) : name(name) {}
        unique_ptr<DNSQuery> asQuery() { return nullptr; } // TODO: unimplemented
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

        unique_ptr<DNSQuery> asQuery() { return nullptr; } 

        string toString() {
            return string(mname.append("\n").append(rname));
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
        unique_ptr<DNSQuery> asQuery() {
            auto dname = this->toString();
            reverse(dname.begin(), dname.end());
            return make_unique<DNSQuery>(DNSQuery(
                dname.append(".in-addr.arpa"),
                0,
                AF_INET,
                addr
            ));
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

        unique_ptr<DNSQuery> asQuery() {
            auto dname = this->toString();
            reverse(dname.begin(), dname.end());
            return make_unique<DNSQuery>(DNSQuery(
                dname.append(".ip6.arpa"),
                0,
                AF_INET6,
                addr
            ));
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
void parse_mx(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &records) {
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

    //record.append("\nMX: ");
    for (int i = 0; i < msg_count; ++i) {
        if ((ret = ns_parserr(&handle, ns_s_an, i, &rr)) < 0) {
            STDERR(hstrerror(ret));
            throw exception();
        }
        cp = (u_char *)ns_rr_rdata(rr);

        // PREFERENCE
        //record.append("\t" + to_string(ns_get16(cp)));

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
        //record.append(" " + string(dname) + "\n");
    }
}

static
void parse_a(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &records) {
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

    //record.append("A: ");

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
        //record.append("\t" + string(buf) + "\n");       
    }
}

static
void parse_aaaa(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &rcords) {
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

    //record.append("AAAA: ");

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
        //record.append("\t" + string(buf) + "\n");       
    }
}

static
void parse_ptr(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &records) {
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

    //record.append("PTR: ");

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
        //record.append("\t" + string(dname) + "\n"); 
    }
}

static // TODO: if SOA not present, parse auth section
void parse_soa(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &records) {
    ns_msg handle;
    ns_rr rr;
    int ret = 0;
    u_char *cp = NULL;
    char dname[NS_MAXDNAME] = {0};
    int msg_count = 0;
    string mname, rname;

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
    mname.append(dname);
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
    rname.append(dname);
    records.push_back(make_unique<SOA>(SOA(mname, rname)));
}

static
vector<unique_ptr<ResourceRecord>> dns2str(unsigned type, const u_char *buffer, int size) { 
    static unordered_map<unsigned, function<void(const u_char *buffer, int size, vector<unique_ptr<ResourceRecord>> &records)>> nsTypeParse {
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

    it->second(buffer, size, records);
    return records;
}

struct RRNode {
    unique_ptr<ResourceRecord> record; 
    vector<struct RRNode> children;  
};

static
void query_test(unique_ptr<DNSQuery> query, vector<RRNode> &root) {
    struct __res_state res;
    res_9_sockaddr_union u[1];
    int ret = 0;
    u_char buf[NS_PACKETSZ] = {0};
    vector<unique_ptr<ResourceRecord>> records;

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
    u[0].sin.sin_addr = query->in;
    u[0].sin.sin_family = AF_INET;  // TODO: IPv6 support
    u[0].sin.sin_port = htons(53);

    res_setservers((res_state) &res, u, 1);
    
    if ((ret = res_nquery(&res, 
                query->dname.c_str(), 
                ns_c_in, query->qtype, 
                buf, 
                sizeof(buf))) > 0) {    // FIXME: not a desired behaviour (e.g. SOA)
        // TODO:
        // parser(response) -> ResourceRecord
        // return make_unique<ResourceRecord>(rr)

        // OLD
        records = dns2str(query->qtype, buf, ret);
    }
    res_ndestroy(&res);
    vector<future<void>> responses;

    while (!records.empty()) {
        root.push_back(RRNode { move(records.back()) });
        records.pop_back();
    }

/*     transform(make_move_iterator(records.begin()), make_move_iterator(records.end()), back_inserter(root),
                    [] (ResourceRecord &r) -> RRNode { return RRNode { make_unique<ResourceRecord>(r) }; }); // FIXME: move clause neccessary?
 */
    for (auto &rrnode : root) {
        for (auto qtype : rrnode.record->asQueryTo()) {
            auto new_q = rrnode.record->asQuery();
            new_q->qtype = qtype;
            responses.push_back(async(launch::async, [&]() { return query_test(move(new_q), rrnode.children); }));
        }
    }
    for (auto &response : responses) {
        response.get();
    }
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
        //record.append(dns2str(type, buf, ret));
    }

    res_ndestroy(&res);
    return record;
}



int main(int argc, const char *argv[]) {

    STDOUT("Trying " << argv[1] << "...\n");
    //vector<future<string>> queries;
    vector<future<void>> responses;

    vector<RRNode> t_aaaa_a;
    vector<RRNode> t_a_a;
    vector<RRNode> t_mx_a;
    vector<RRNode> t_soa_a;

    try {
        struct in_addr in;
        if (inet_pton(AF_INET, argv[2], &in) != 1) {
            exit(EXIT_FAILURE);
        }
        unique_ptr<DNSQuery> t_aaaa(new DNSQuery(argv[1], QTYPE::aaaa, AF_INET, in));
        unique_ptr<DNSQuery> t_a(new DNSQuery(argv[1], QTYPE::a, AF_INET, in));
        unique_ptr<DNSQuery> t_mx(new DNSQuery(argv[1], QTYPE::mx, AF_INET, in));
        unique_ptr<DNSQuery> t_soa(new DNSQuery(argv[1], QTYPE::soa, AF_INET, in));

       /*  queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_aaaa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_a, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_soa, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_mx, in); }));
        queries.push_back(async(launch::async, [&]() { return query(argv[1], ns_t_ptr, in); }));
 */
        responses.push_back(async(launch::async, [&]() { return query_test(move(t_aaaa), t_aaaa_a); }));   // AAAA(s)
        responses.push_back(async(launch::async, [&]() { return query_test(move(t_a), t_a_a); }));   // AAAA(s)
        responses.push_back(async(launch::async, [&]() { return query_test(move(t_mx), t_mx_a); }));   // AAAA(s)
        responses.push_back(async(launch::async, [&]() { return query_test(move(t_soa), t_soa_a); }));   // AAAA(s)
        // ...


        STDOUT("========= DNS =========\n");

    }
    catch(...) {
         exit(EXIT_FAILURE);
    }


    return EXIT_SUCCESS;
}


//  TODO: debug __LINE__ msgs
// TODO: data tree ontainer