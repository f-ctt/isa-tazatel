#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <string.h>
#include <resolv.h>
#include <future>
#include <netdb.h>      // hstrerror

#include "dns_resolver.h"
#include "helpers.h"

static sockaddr_storage DNS_SADDR;
static int TAR_AFINET_DNS = 0;

void set_dns(char *dnsip) {
    if (inet_pton(AF_INET, dnsip, &((sockaddr_in *)&DNS_SADDR)->sin_addr) != 1) {
        if (inet_pton(AF_INET6, dnsip, &((sockaddr_in6 *)&DNS_SADDR)->sin6_addr) != 1) {
            STDERR(dnsip << " is not a valid IP");
            exit(EXIT_FAILURE);
        }
        TAR_AFINET_DNS = AF_INET6;
        return;
    } 
    TAR_AFINET_DNS = AF_INET;
}

void RecordNode::printTree(const std::string &prefix, bool last) {
    std::cout << prefix << (last ? "└──" : "├──");
    auto desc = record->descr();
    std::cout << desc;
    for (size_t i = 0; i < 6 - strlen(desc); ++i)
        std::cout << "─";
    std::cout << record->toString() << std::endl;
    unsigned cnt = 0;
    for (auto &ch : children) {
        cnt++;
        bool lst = (cnt == children.size());
        ch.printTree(prefix + (last ? "         " : "|         "), lst);
    }
}


MX::MX(uint16_t pref, std::string exch) : pref(pref), exch(exch) {}
const char *MX::descr() const { return "MX"; }
std::string MX::asQuery() { return std::string(); }
std::string MX::toString() { return std::string(std::to_string(pref).append(" ") + exch); }
unsigned MX::qtype() const { return QTYPE::mx; }
std::vector<QTYPE> MX::asQueryTo() { return std::vector<QTYPE>(); }


CNAME::CNAME(std::string cname) : cname(cname) {}
const char *CNAME::descr() const { return "CNAME"; }
std::string CNAME::asQuery() { return cname; }
unsigned CNAME::qtype() const { return QTYPE::cname; }
std::vector<QTYPE> CNAME::asQueryTo() { return std::vector<QTYPE>(); } // TODO: unimplemented
std::string CNAME::toString() { return cname; }


PTR::PTR(std::string name) : name(name) {}
const char *PTR::descr() const { return "PTR"; }
std::string PTR::asQuery() { return this->toString(); } 
unsigned PTR::qtype() const { return QTYPE::ptr; }
std::vector<QTYPE> PTR::asQueryTo() { 
    return std::vector<QTYPE>
        {
            QTYPE::a,
            QTYPE::aaaa,
            QTYPE::mx,
            QTYPE::soa
        }; 
}
std::string PTR::toString() { return name; };


SOA::SOA(std::string mname, std::string rname) : mname(mname), rname(rname) {}
const char* SOA::descr() const { return "SOA"; }
std::vector<QTYPE> SOA::asQueryTo() { return std::vector<QTYPE>(); }
unsigned SOA::qtype() const { return QTYPE::soa; }
std::string SOA::asQuery() { return std::string(); } 
std::string SOA::toString() {
    return std::string(mname.append(" ").append(rname));
}


A::A(struct in_addr addr) : addr(addr) {}
std::vector<QTYPE> A::asQueryTo() { return std::vector<QTYPE>{ QTYPE::ptr }; }
const char *A::descr() const { return "A"; }
unsigned A::qtype() const { return QTYPE::a; } 
struct in_addr A::inaddr() { return addr; }
std::string A::toString() {
    char buf[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == NULL)
        throw std::runtime_error("inet_ntop zhorel a nemel v A");
    return std::string(buf);
}
std::string A::asQuery() {
    struct in_addr tmp = addr;
    addr.s_addr = htonl(addr.s_addr);
    auto dname = this->toString();
    addr = tmp;
    return dname.append(".in-addr.arpa");
}


NS::NS(std::string name) : name(name) {}
std::vector<QTYPE> NS::asQueryTo() { return std::vector<QTYPE>(); } // TODO: unimplemented
unsigned NS::qtype() const { return QTYPE::ns; }
std::string NS::toString() { return name; }
std::string NS::asQuery() { return name; }
const char* NS::descr() const { return "NS"; }


AAAA::AAAA(struct in6_addr addr) : addr(addr) {}
const char* AAAA::descr() const { return "AAAA"; }
std::vector<QTYPE> AAAA::asQueryTo() { return std::vector<QTYPE>{ QTYPE::ptr }; }
unsigned AAAA::qtype() const { return QTYPE::aaaa; }
struct in6_addr AAAA::in6addr() { return addr; }
std::string AAAA::toString() {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf)) == NULL)
        throw std::runtime_error("inet_ntop zhorel v AAAA");
    return std::string(buf);
}
// source: https://git.busybox.net/busybox/plain/networking/nslookup.c 
// FIXME: not really a protable code due to the inner members of 'addr'
std::string AAAA::asQuery() {
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
        return std::string(resbuf);
    }
    snprintf(resbuf, sizeof(resbuf), "%u.%u.%u.%u.in-addr.arpa",
            addr.__in6_u.__u6_addr8[15], 
            addr.__in6_u.__u6_addr8[14], 
            addr.__in6_u.__u6_addr8[13], 
            addr.__in6_u.__u6_addr8[12]);
    return std::string(resbuf);
}

using namespace std;

static
void res_nfree(res_state state) {
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
int setservers(res_state state, int af) {
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

RecordNodes dns_nquery(string hname, QTYPE qt, unsigned ttl) {
    struct __res_state resstate;
    int ret = 0;
    union {
        HEADER h;
        u_char buf[NS_PACKETSZ] = {0};
    } response;

    vector<unique_ptr<Record>> records; 
    vector<future<vector<RecordNode>>> responses;
    vector<RecordNode> root;

    memset(&resstate, 0, sizeof(struct __res_state));
    if ((ret = res_ninit(&resstate)) < 0)
        throw runtime_error(hstrerror(ret));

    if (TAR_AFINET_DNS) {
        if (setservers(&resstate, TAR_AFINET_DNS))
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
                response.buf, 
                sizeof(response))) > 0) {  
        records = parsedns(response.buf, ret, ns_s_an, qt);
    } else if (qt == QTYPE::soa && response.h.nscount && !response.h.rcode) { // Test if there is a msg in authoritative section
        // res_nquery returns -1, need to get the total len manually
        int cnt = 512;
        while (response.buf[--cnt] == '\0' && cnt > 0); 
        records = parsedns(response.buf, cnt + 1, ns_s_ns, qt); // cnt + 1 -> idx + 1 to get the total len
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
                    [ttl, qtype, s = move(new_q)](){ return dns_nquery(s, qtype, ttl - 1); }));
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
    res_nfree(&resstate);
    return root;
}
