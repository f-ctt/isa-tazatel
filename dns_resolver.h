#pragma once

#include <memory>
#include <vector>
#include <string>

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
        virtual std::string toString() = 0;
        virtual std::string asQuery() = 0;
        virtual unsigned qtype() const = 0;
        virtual std::vector<QTYPE> asQueryTo() = 0;
        virtual ~Record() {};
};

using RecordPtr = std::unique_ptr<Record>;
using Records = std::vector<RecordPtr>;

class MX : public Record {
    private:
        uint16_t pref;
        std::string exch;
    public:
        MX(uint16_t pref, std::string exch);
        const char *descr() const;
        std::string asQuery();
        std::string toString();
        unsigned qtype() const;
        std::vector<QTYPE> asQueryTo();
};

class CNAME: public Record {
    private:
        std::string cname;
    public:
        CNAME(std::string cname);
        const char *descr() const;
        std::string asQuery();
        unsigned qtype() const;
        std::vector<QTYPE> asQueryTo();
        std::string toString();
};

class PTR : public Record {
    private:
        std::string name;
    public:
        PTR(std::string name);
        const char *descr() const;
        std::string asQuery();
        unsigned qtype() const;
        std::vector<QTYPE> asQueryTo();
        std::string toString();
};

class SOA : public Record {
    private:
        std::string mname;
        std::string rname;
    public:
        SOA(std::string mname, std::string rname);
        const char *descr() const;
        std::vector<QTYPE> asQueryTo();
        unsigned qtype() const;
        std::string asQuery();
        std::string toString();
};

class A : public Record {
    private:
        struct in_addr addr;
    public:
        A(struct in_addr addr);
        std::vector<QTYPE> asQueryTo();
        const char *descr() const;
        unsigned qtype() const;
        struct in_addr inaddr();
        std::string toString();
        std::string asQuery();
};

class NS: public Record {
    private:
        std::string name;
    public:
        NS(std::string name);
        std::vector<QTYPE> asQueryTo();
        unsigned qtype() const;
        std::string toString(); 
        std::string asQuery();
        const char *descr() const;
};

class AAAA : public Record {
    private:
        struct in6_addr addr;
    public:
        AAAA(struct in6_addr addr);
        const char *descr() const;
        std::vector<QTYPE> asQueryTo();
        unsigned qtype() const;
        struct in6_addr in6addr();
        std::string toString();
        std::string asQuery();
};

struct RecordNode {
    RecordPtr record; 
    std::vector<struct RecordNode> children;
    void printTree(const std::string &prefix, bool last);
};

void set_dns(char *dnsip);

using RecordNodes = std::vector<RecordNode>;
RecordNodes dns_nquery(std::string hname, QTYPE qt, unsigned ttl);
