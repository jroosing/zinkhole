//! Building responses: the shapes zinkhole answers with itself (local,
//! reverse, blocked, negative and error answers), and fitting an upstream or
//! cached answer to the client that asked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::BlockResponse;
use crate::policy::Blocked;

/// The UDP payload size zinkhole advertises, and asks upstream servers for:
/// large enough for most answers, small enough to avoid IP fragmentation
/// (DNS Flag Day 2020).
pub const EDNS_PAYLOAD: u16 = 1232;
/// What a client without EDNS accepts over UDP.
pub const MIN_UDP_PAYLOAD: u16 = 512;
/// The size of a DNS header.
pub const HEADER_LEN: usize = 12;

/// The made-up zone of the SOA in negative answers (`.invalid`, RFC 6761).
const SOA_MNAME: &str = "zinkhole.invalid.";
const SOA_RNAME: &str = "hostmaster.zinkhole.invalid.";

/// An empty response to `query`: its ID, opcode, RD and CD flags, its
/// question as the client wrote it, and an OPT record if the client sent one.
#[must_use]
pub fn response(query: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.queries.clone_from(&query.queries);
    response.edns = query
        .edns
        .as_ref()
        .map(|edns| fresh_edns(edns.flags().dnssec_ok));
    response
}

/// An OPT record without options: client cookies, client subnet and the like
/// are never passed on.
#[must_use]
pub fn fresh_edns(dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    edns
}

/// The addresses of a local record or a block response that the question asks
/// for: A and AAAA records, both for ANY. For other types the name exists
/// but has nothing of that type (NODATA, with an SOA for `ttl`).
#[must_use]
pub fn addresses(query: &Message, addresses: &[IpAddr], ttl: u32, authoritative: bool) -> Message {
    let mut response = response(query, ResponseCode::NoError);
    response.metadata.authoritative = authoritative;
    let Some(question) = query.queries.first() else {
        return response;
    };
    let qtype = question.query_type();
    let owner = question.name().clone();
    for address in addresses {
        let data = match (address, qtype) {
            (IpAddr::V4(ip), RecordType::A | RecordType::ANY) => RData::A(A(*ip)),
            (IpAddr::V6(ip), RecordType::AAAA | RecordType::ANY) => RData::AAAA(AAAA(*ip)),
            _ => continue,
        };
        response
            .answers
            .push(Record::from_rdata(owner.clone(), ttl, data));
    }
    if response.answers.is_empty() {
        add_soa(&mut response, ttl);
    }
    response
}

/// The name of a local record whose address a reverse lookup asks for.
#[must_use]
pub fn reverse(query: &Message, host: &str, ttl: u32) -> Message {
    let mut response = response(query, ResponseCode::NoError);
    response.metadata.authoritative = true;
    let (Some(question), Ok(target)) =
        (query.queries.first(), Name::from_ascii(format!("{host}.")))
    else {
        return response;
    };
    response.answers.push(Record::from_rdata(
        question.name().clone(),
        ttl,
        RData::PTR(PTR(target)),
    ));
    response
}

/// The block response: zero addresses (an empty answer for other types) or
/// NXDOMAIN, both cacheable by clients for the block TTL.
#[must_use]
pub fn blocked(query: &Message, blocked: Blocked) -> Message {
    match blocked.response {
        BlockResponse::Zero => addresses(
            query,
            &[
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ],
            blocked.ttl,
            false,
        ),
        BlockResponse::Nxdomain => negative(query, ResponseCode::NXDomain, blocked.ttl),
    }
}

/// NXDOMAIN, or an empty NOERROR answer, with an SOA so clients cache it for
/// `ttl` (RFC 2308).
#[must_use]
pub fn negative(query: &Message, code: ResponseCode, ttl: u32) -> Message {
    let mut response = response(query, code);
    add_soa(&mut response, ttl);
    response
}

/// An SOA owned by the question name, so it covers exactly this answer; its
/// TTL and MINIMUM are the negative TTL.
fn add_soa(response: &mut Message, ttl: u32) {
    let Some(owner) = response.queries.first().map(|q| q.name().clone()) else {
        return;
    };
    let (Ok(mname), Ok(rname)) = (Name::from_str(SOA_MNAME), Name::from_str(SOA_RNAME)) else {
        return;
    };
    let soa = SOA::new(mname, rname, 1, 3600, 600, 86_400, ttl);
    response
        .authorities
        .push(Record::from_rdata(owner, ttl, RData::SOA(soa)));
}

/// `answer` (from an upstream server or the cache) fitted to `query`: the
/// client's ID, flags and spelling of the question, and its EDNS. DNSSEC
/// data only for a client that asked for it (DO): signatures and denial
/// records are left out otherwise, and AD is set only for a client that set
/// DO or AD (RFC 6840).
#[must_use]
pub fn for_client(query: &Message, mut answer: Message) -> Message {
    let dnssec_ok = query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    answer.metadata.authentic_data &= dnssec_ok || query.metadata.authentic_data;
    if !dnssec_ok {
        let asked = query.queries.first().map(Query::query_type);
        let keep = |record: &Record| {
            let kind = record.record_type();
            Some(kind) == asked
                || !matches!(
                    kind,
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                )
        };
        answer.answers.retain(keep);
        answer.authorities.retain(keep);
        answer.additionals.retain(keep);
    }
    answer.metadata.id = query.metadata.id;
    answer.metadata.message_type = MessageType::Response;
    answer.metadata.recursion_desired = query.metadata.recursion_desired;
    answer.metadata.checking_disabled = query.metadata.checking_disabled;
    answer.metadata.recursion_available = true;
    answer.metadata.truncation = false;
    answer.queries.clone_from(&query.queries);
    answer.edns = query
        .edns
        .as_ref()
        .map(|edns| fresh_edns(edns.flags().dnssec_ok));
    answer.signature = None;
    answer
}

/// The same response with no records and TC set: the client retries over TCP.
#[must_use]
pub fn truncated(response: &Message) -> Message {
    let mut truncated = Message::response(response.metadata.id, response.metadata.op_code);
    truncated.metadata = response.metadata;
    truncated.metadata.truncation = true;
    truncated.queries.clone_from(&response.queries);
    truncated.edns.clone_from(&response.edns);
    truncated
}

/// A bare error response repeating only the header of a query that could not
/// be parsed. None if `query` is not even a header, or is itself a response.
#[must_use]
pub fn header_only(query: &[u8], code: ResponseCode) -> Option<Vec<u8>> {
    let header = query.get(..HEADER_LEN)?;
    let (Some(&id_high), Some(&id_low), Some(&flags_high)) =
        (header.first(), header.get(1), header.get(2))
    else {
        return None;
    };
    if flags_high & 0x80 != 0 {
        return None; // QR: a response, never answered
    }
    let mut response = Message::response(
        u16::from_be_bytes([id_high, id_low]),
        OpCode::from_u8((flags_high >> 3) & 0x0f),
    );
    response.metadata.recursion_desired = flags_high & 0x01 != 0;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.to_vec().ok()
}

/// The largest response to `query` sent over UDP: what its sender takes,
/// but never more than [`EDNS_PAYLOAD`], so answers are not fragmented
/// (larger ones get TC and go over TCP).
#[must_use]
pub fn max_udp_size(query: &Message) -> usize {
    let advertised = query
        .edns
        .as_ref()
        .map_or(MIN_UDP_PAYLOAD, Edns::max_payload);
    usize::from(advertised.clamp(MIN_UDP_PAYLOAD, EDNS_PAYLOAD))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn query(name: &str, qtype: RecordType, edns: bool) -> Message {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        if edns {
            let mut client = Edns::new();
            client.set_max_payload(4096);
            client.set_dnssec_ok(true);
            query.edns = Some(client);
        }
        query
    }

    fn round_trip(message: &Message) -> Message {
        Message::from_vec(&message.to_vec().unwrap()).unwrap()
    }

    #[test]
    fn dnssec_data_and_ad_reach_only_clients_that_ask_for_them() {
        use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC};
        let upstream = |q: &Message| {
            let mut answer = response(q, ResponseCode::NoError);
            answer.metadata.authentic_data = true;
            let name = q.queries[0].name().clone();
            answer.answers.push(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A([1, 2, 3, 4].into())),
            ));
            let nsec = NSEC::new(Name::from_ascii("z.example.").unwrap(), [RecordType::A]);
            answer.authorities.push(Record::from_rdata(
                name,
                60,
                RData::DNSSEC(DNSSECRData::NSEC(nsec)),
            ));
            answer
        };
        let check = |q: Message, ad: bool, nsec: usize| {
            let answer = for_client(&q, upstream(&q));
            assert_eq!(
                answer.metadata.authentic_data, ad,
                "AD for {:?}",
                q.metadata
            );
            assert_eq!(answer.authorities.len(), nsec, "NSEC kept");
        };
        check(query("example.com.", RecordType::A, true), true, 1); // DO
        check(query("example.com.", RecordType::A, false), false, 0); // neither
        let mut ad_only = query("example.com.", RecordType::A, false);
        ad_only.metadata.authentic_data = true;
        check(ad_only, true, 0); // AD, no DO: the bit, not the records
        check(query("example.com.", RecordType::NSEC, false), false, 1); // asked for
    }

    #[test]
    fn addresses_follow_the_question_type() {
        let ips: Vec<IpAddr> = vec!["192.168.1.10".parse().unwrap(), "fd00::10".parse().unwrap()];
        let a = round_trip(&addresses(
            &query("NAS.lan.", RecordType::A, false),
            &ips,
            120,
            true,
        ));
        assert!(
            a.metadata.authoritative
                && a.metadata.recursion_desired
                && a.metadata.recursion_available
        );
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].ttl, 120);
        assert_eq!(
            a.answers[0].name.to_string(),
            "NAS.lan.",
            "the client's spelling"
        );
        assert_eq!(a.authorities.len(), 0);

        let any = round_trip(&addresses(
            &query("nas.lan.", RecordType::ANY, false),
            &ips,
            120,
            true,
        ));
        assert_eq!(any.answers.len(), 2);

        // The name exists, but has no record of this type: NODATA with an SOA.
        let mx = round_trip(&addresses(
            &query("nas.lan.", RecordType::MX, false),
            &ips,
            120,
            true,
        ));
        assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
        assert_eq!(mx.answers.len(), 0);
        let RData::SOA(soa) = &mx.authorities[0].data else {
            panic!("SOA expected")
        };
        assert_eq!((mx.authorities[0].ttl, soa.minimum), (120, 120));
    }

    #[test]
    fn blocked_names_get_zero_addresses_or_nxdomain() {
        let zero = Blocked {
            response: BlockResponse::Zero,
            ttl: 30,
        };
        let a = round_trip(&blocked(
            &query("ads.example.com.", RecordType::A, false),
            zero,
        ));
        assert!(!a.metadata.authoritative);
        assert_eq!(a.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        let aaaa = round_trip(&blocked(
            &query("ads.example.com.", RecordType::AAAA, false),
            zero,
        ));
        assert_eq!(
            aaaa.answers[0].data,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
        );
        // No way around a block through other record types.
        let https = round_trip(&blocked(
            &query("ads.example.com.", RecordType::HTTPS, false),
            zero,
        ));
        assert!(https.answers.is_empty() && https.authorities.len() == 1);

        let nx = Blocked {
            response: BlockResponse::Nxdomain,
            ttl: 45,
        };
        let response = round_trip(&blocked(
            &query("ads.example.com.", RecordType::A, false),
            nx,
        ));
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.authorities[0].ttl, 45);
    }

    #[test]
    fn edns_is_answered_with_our_payload_size_and_the_do_bit() {
        let response = round_trip(&negative(
            &query("printer.", RecordType::A, true),
            ResponseCode::NXDomain,
            300,
        ));
        let edns = response
            .edns
            .expect("an OPT record, because the client sent one");
        assert_eq!(edns.max_payload(), EDNS_PAYLOAD);
        assert!(edns.flags().dnssec_ok);
        let plain = round_trip(&negative(
            &query("printer.", RecordType::A, false),
            ResponseCode::NXDomain,
            300,
        ));
        assert!(plain.edns.is_none());
    }

    #[test]
    fn reverse_answers_name_the_host() {
        let response = round_trip(&reverse(
            &query("10.1.168.192.in-addr.arpa.", RecordType::PTR, false),
            "nas.lan",
            60,
        ));
        assert_eq!(
            response.answers[0].data,
            RData::PTR(PTR(Name::from_str("nas.lan.").unwrap()))
        );
    }

    #[test]
    fn header_only_answers_keep_the_id_and_skip_responses() {
        let mut bytes = query("x.example.", RecordType::A, false).to_vec().unwrap();
        bytes.truncate(14); // a header and garbage
        let response =
            Message::from_vec(&header_only(&bytes, ResponseCode::FormErr).unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
        assert!(response.metadata.recursion_desired);
        assert_eq!(header_only(&bytes[..5], ResponseCode::FormErr), None);
        bytes[2] |= 0x80;
        assert_eq!(header_only(&bytes, ResponseCode::FormErr), None);
    }

    #[test]
    fn max_udp_size_is_between_512_and_1232() {
        assert_eq!(max_udp_size(&query("x.", RecordType::A, false)), 512);
        // The client offers 4096; fragments are avoided all the same.
        assert_eq!(max_udp_size(&query("x.", RecordType::A, true)), 1232);
    }
}
