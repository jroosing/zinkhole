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
The fixed order in which a query is checked: allowed client, local record, blocked name, private name, cache, upstream server. The first step that applies decides the answer.
_Avoid_: resolution chain, filter chain

**Outcome**:
How a single query was answered: local, blocked, private, cached, forwarded, failed, refused or invalid.
_Avoid_: result, status

**Policy**:
Everything zinkhole uses to answer a name without asking an upstream server: local records, rules and private names.
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
A name matched by at least one block rule and no allow rule.

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
A name that cannot exist on the public internet, such as `.lan`, `.home.arpa`, `.internal`, single-label names and reverse lookups of private addresses. It is never sent to upstream servers unless forwarding of private names is configured.
_Avoid_: special-use name, internal name, LAN name

### Upstream

**Upstream server**:
A public DNS server that answers the queries zinkhole does not answer itself. Upstream servers are tried in order, and the next one is used when one fails.
_Avoid_: resolver, forwarder, backend

### Lifecycle

**Reload**:
Applying a changed config file to a running server. Local records and inline rules take effect immediately; lists are downloaded again only if their sources changed.
_Avoid_: restart, refresh

**Refresh**:
Downloading every list again from its source on a timer, without any config change.
_Avoid_: reload, update
