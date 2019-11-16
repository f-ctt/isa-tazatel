## Whois supercalifragilisticexpialidocious whisperer (isa-tazatel)

__This project is one of the objectives for [ISA](https://www.fit.vut.cz/study/course/ISA/)__

__Isa-tazatel__ is a whois and a DNS lookup tool written in C/C++ using the linux resolver library(resolv.h) and BSD sockets.

It's been tested on __Ubuntu 18.04.3 LTS__ and __Fedora 30__

More information can be found in __manual.pdf__
### List of submitted files 
dns-resolver.cpp\
dns-resolver.h\
whois.cpp\
whois.h\
helpers.cpp\
helpers.h\
isa-tazatel.cpp\
Makefile\
README.md

### Example

```shell
$ isa-tazatel -q fit.vut.cz -w whois.iana.org -d 1.1.1.1
```
```
========= DNS =========

fit.vut.cz
    ├──A─────147.229.9.26
    |         └──PTR───www.fit.vut.cz
    |                  ├──A─────147.229.9.26
    |                  ├──AAAA──2001:67c:1220:809::93e5:91a
    |                  ├──MX────10 kazi.fit.vutbr.cz
    |                  └──SOA───guta.fit.vutbr.cz michal.fit.vutbr.cz
    ├──SOA───guta.fit.vutbr.cz michal.fit.vutbr.cz
    ├──AAAA──2001:67c:1220:809::93e5:91a
    |         └──PTR───www.fit.vut.cz
    |                  ├──A─────147.229.9.26
    |                  ├──AAAA──2001:67c:1220:809::93e5:91a
    |                  ├──MX────10 kazi.fit.vutbr.cz
    |                  └──SOA───guta.fit.vutbr.cz michal.fit.vutbr.cz
    ├──MX────10 kazi.fit.vutbr.cz
    ├──NS────rhino.cis.vutbr.cz
    ├──NS────kazi.fit.vutbr.cz
    ├──NS────guta.fit.vutbr.cz
    └──NS────gate.feec.vutbr.cz

========= WHOIS =========

% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '147.229.0.0 - 147.229.254.255'

% Abuse contact for '147.229.0.0 - 147.229.254.255' is 'abuse@vutbr.cz'

inetnum:        147.229.0.0 - 147.229.254.255
netname:        VUTBRNET
descr:          Brno University of Technology
country:        CZ
admin-c:        CA6319-RIPE
tech-c:         CA6319-RIPE
status:         ASSIGNED PA
mnt-by:         VUTBR-MNT
created:        2014-11-19T08:23:45Z
last-modified:  2015-01-30T08:37:07Z
source:         RIPE

role:           Brno University of Technology - Backbone Admins
address:        Brno University of Technology
address:        Antoninska 1
address:        601 90 Brno
address:        The Czech Republic
phone:          +420 541145453
phone:          +420 723047787
nic-hdl:        CA6319-RIPE
mnt-by:         VUT-BATCH-MNT
mnt-by:         VUTBR-MNT
created:        2015-01-30T08:31:35Z
last-modified:  2016-11-04T14:01:52Z
source:         RIPE # Filtered
abuse-mailbox:  abuse@vutbr.cz

% Information related to '147.229.0.0/17AS197451'

route:          147.229.0.0/17
descr:          VUTBR-NET1
origin:         AS197451
mnt-by:         VUTBR-MNT
created:        2014-12-04T19:07:00Z
last-modified:  2014-12-04T19:07:00Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.95.1 (ANGUS)

```