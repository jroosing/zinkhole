# zinkhole

A DNS blocker and local DNS server for a home network. It answers names for the network's own devices, blocks ad and tracker domains from lists, and forwards everything else to upstream servers.

## Language

### Queries

**Client**:
A device on the network that sends DNS queries to zinkhole.
_Avoid_: user, host

**Allowed client**:
A client whose address falls inside one of the configured client networks; every other client is refused.
_Avoid_: trusted client, whitelisted client

**Query pipeline**:
The fixed order in which a query is checked: allowed client, local record, blocked name, forwarded zone, private name, cache, upstream server. The first step that applies decides the answer; a name in a forwarded zone is then answered from the cache or by the zone's server.
_Avoid_: resolution chain, filter chain

**Outcome**:
How a single query was answered: local, blocked, private, cached, forwarded, failed, refused or invalid.
_Avoid_: result, status

**Metrics**:
Counts of Outcomes and of upstream server attempts per local hour for the last 24 hours (so also "today", since 00:00 local time), plus the current state of the lists, sync and the instance. Kept in memory only: a restart starts them from zero. Served as JSON at `GET /metrics` (ADR-0004).
_Avoid_: stats, statistics, telemetry

**Policy**:
Everything zinkhole uses to decide how a name is answered before asking an upstream server: local records, rules, forwarded zones and private names.
_Avoid_: rules, filter

### Blocking

**Rule**:
One block or allow entry for a domain. A plain domain matches itself and all of its subdomains; a wildcard matches only the subdomains.
_Avoid_: entry, filter, pattern

**Block rule**:
A rule that makes matching names blocked names.

**Allow rule**:
A rule that exempts matching names from blocking. An allow rule always wins over a block rule.
_Avoid_: exception, whitelist entry

**Inline rule**:
A rule written directly in the config file rather than in a list.

**List**:
A blocklist or an allowlist: a collection of rules loaded from a source, in any supported list format.

**Blocklist**:
A list whose rules are block rules (Adblock `@@` exceptions inside it are still allow rules).
_Avoid_: filter list, adlist, hosts file

**Allowlist**:
A list whose rules are all allow rules.
_Avoid_: whitelist, exception list

**Source**:
The URL or file path a list is loaded from.
_Avoid_: feed, subscription

**Blocked name**:
A name matched by at least one block rule and no allow rule. An upstream answer that makes a name an alias (CNAME) of a blocked name is blocked too, unless an allow rule matches the name asked for.

**Block response**:
How blocked names are answered: zero addresses (`0.0.0.0` / `::`) or NXDOMAIN.
_Avoid_: sinkhole address

### Local DNS

**Local record**:
A hostname configured for one of the network's own devices or apps, with one or more addresses. Answered by zinkhole itself, ahead of any blocking.
_Avoid_: custom DNS entry, static host, DNS override

**Wildcard**:
A `*.name` pattern that matches every name below `name` but not `name` itself. Used by both local records and rules.

**Reverse lookup**:
A query for the name that belongs to an address (PTR), answered from the local records.

**Private name**:
A name that cannot exist on the public internet, such as `.lan`, `.home.arpa`, `.internal`, single-label names and reverse lookups of private addresses. It is never sent to upstream servers unless forwarding of private names is configured, and is sent to a zone's server when it is in a forwarded zone.
_Avoid_: special-use name, internal name, LAN name

**Forwarded zone**:
A zone (such as `lan` or `1.168.192.in-addr.arpa`) whose names are sent to a server of its own instead of the upstream servers, typically the router that knows its DHCP clients' names. Local records and rules still apply first.
_Avoid_: conditional forwarder, stub zone

### Upstream

**Upstream server**:
A public DNS server that answers the queries zinkhole does not answer itself. Upstream servers are tried in order, and the next one is used when one fails.
_Avoid_: resolver, forwarder, backend

### Redundancy

**Origin**:
The zinkhole instance whose config file is the source of truth for the Policy settings (local records, rules, lists); it serves them to replicas. Every instance answers queries alike; the role only says where settings come from.
_Avoid_: master, primary, leader

**Replica**:
A zinkhole instance that takes its Policy settings from the origin. Its own config file holds only what is specific to it, such as listen addresses and upstream servers.
_Avoid_: worker, slave, secondary

**Sync**:
A replica fetching the origin's settings, checking them and applying them.
_Avoid_: push, replication

### Lifecycle

**Reload**:
Applying a changed config file to a running server. Local records and inline rules take effect immediately; lists are downloaded again only if their sources changed.
_Avoid_: restart, refresh

**Refresh**:
Downloading every list again from its source on a timer, without any config change.
_Avoid_: reload, update
