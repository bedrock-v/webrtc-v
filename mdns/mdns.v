// Package mdns resolves the ".local" names that appear in ICE candidates.
//
// A browser does not put its private addresses in an offer any more. It
// registers a random name like "d4f4c2b0-....local" with multicast DNS and
// signals that instead (RFC 8828). A peer that cannot resolve the name loses
// the host candidate, and with it every local-network path - which is usually
// the fastest one there is.
//
// This is a resolver only. Being a responder means registering a name and
// answering queries for it, which is what the privacy half of RFC 8828 needs;
// it is not implemented, so this end's own candidates carry addresses.
module mdns

import net
import time
import webrtc.internal.codec
import webrtc.netaddr
import webrtc.transport

// multicast_group_v4 and multicast_group_v6 are where a query goes. Both are
// link-local, so a query never leaves the network segment.
pub const multicast_group_v4 = '224.0.0.251:5353'
pub const multicast_group_v6 = '[ff02::fb]:5353'

// max_response is the largest response accepted. A multicast DNS response
// carrying an address is a few hundred bytes; anything much larger is either
// not for us or is trying to make us do work.
pub const max_response = 4096

// max_name_labels bounds how many labels a name may have, and
// max_pointer_hops bounds how many compression pointers are followed. Both stop
// a crafted response from making the parser loop: a pointer that points at
// itself is the classic decompression bomb.
const max_name_labels = 128
const max_pointer_hops = 16

// record types and classes, the only ones this resolver uses.
const type_a = u16(1)
const type_aaaa = u16(28)
const class_in = u16(1)

// unicast_response_bit asks the responder to answer directly to the querier's
// port rather than to the multicast group.
//
// Without it the answer goes to the group on port 5353, which can only be read
// by a socket bound to that port - and on most machines that port already
// belongs to the system responder. Setting it is what lets this work as an
// ordinary client. A responder that ignores the bit will not be heard, which is
// the known limit of this approach.
const unicast_response_bit = u16(0x8000)

// MdnsError is returned when a name cannot be resolved.
pub struct MdnsError {
pub:
	reason MdnsErrorReason
	detail string
}

pub enum MdnsErrorReason {
	// not_local: the name is not a .local name, so this resolver is the wrong
	// tool rather than having failed.
	not_local
	// bad_name: the name is malformed or too long to encode.
	bad_name
	// transport: a socket operation failed.
	transport
	// timed_out: nothing answered.
	timed_out
	// bad_response: something answered with a message that does not decode.
	bad_response
}

pub fn (e MdnsError) msg() string {
	return 'mdns: ${e.reason}: ${e.detail}'
}

pub fn (e MdnsError) code() int {
	return int(e.reason) + 80
}

// is_local_name reports whether a host is one this resolver handles.
pub fn is_local_name(host string) bool {
	lower := host.to_lower()
	return lower.ends_with('.local') || lower.ends_with('.local.')
}

// resolve looks up the address for a .local name.
//
// Both families are asked for in one query round: an ICE candidate names one
// address, and which family it is cannot be known in advance.
pub fn resolve(name string, timeout time.Duration) !netaddr.IpAddr {
	if !is_local_name(name) {
		return MdnsError{
			reason: .not_local
			detail: '"${name}" is not a .local name'
		}
	}

	question := encode_query(name)!
	mut conn := net.listen_udp('0.0.0.0:0') or {
		return MdnsError{
			reason: .transport
			detail: 'binding a query socket: ${err.msg()}'
		}
	}
	defer {
		conn.close() or {}
	}

	// The group address is a literal, so it is built directly rather than
	// resolved: a name lookup here would be a DNS query to answer a DNS query.
	group_address := netaddr.SocketAddr.parse(multicast_group_v4) or {
		return MdnsError{
			reason: .transport
			detail: err.msg()
		}
	}
	group := transport.socket_addr_to_net(group_address) or {
		return MdnsError{
			reason: .transport
			detail: err.msg()
		}
	}
	conn.write_to(group, question) or {
		return MdnsError{
			reason: .transport
			detail: 'sending the query: ${err.msg()}'
		}
	}

	deadline := time.now().add(timeout)
	for {
		remaining := deadline - time.now()
		if remaining <= 0 {
			break
		}
		conn.set_read_timeout(remaining)
		mut buf := []u8{len: max_response}
		n, _ := conn.read(mut buf) or { break }
		if n <= 0 {
			continue
		}
		if address := answer_for(buf[..n], name) {
			return address
		}
	}

	return MdnsError{
		reason: .timed_out
		detail: 'no answer for "${name}" within ${timeout.milliseconds()}ms'
	}
}

// encode_query builds a query for both address families.
fn encode_query(name string) ![]u8 {
	mut w := codec.Writer.new()
	// A transaction id of zero: multicast DNS matches on the question, not on
	// the id, and RFC 6762 section 18.1 says a querier sets it to zero.
	w.u16(0)
	w.u16(0) // flags: a standard query
	w.u16(2) // two questions, one per family
	w.u16(0) // no answers
	w.u16(0) // no authority records
	w.u16(0) // no additional records

	encoded := encode_name(name)!
	w.bytes(encoded)
	w.u16(type_a)
	w.u16(class_in | unicast_response_bit)

	w.bytes(encoded)
	w.u16(type_aaaa)
	w.u16(class_in | unicast_response_bit)
	return w.buf
}

// encode_name writes a name in the wire format: each label length-prefixed,
// terminated by a zero length.
fn encode_name(name string) ![]u8 {
	trimmed := name.trim_right('.')
	mut w := codec.Writer.new()
	for label in trimmed.split('.') {
		if label.len == 0 {
			return MdnsError{
				reason: .bad_name
				detail: 'an empty label in "${name}"'
			}
		}
		if label.len > 63 {
			return MdnsError{
				reason: .bad_name
				detail: 'the label "${label}" is longer than 63 bytes'
			}
		}
		w.u8(u8(label.len))
		w.bytes(label.bytes())
	}
	w.u8(0)
	if w.buf.len > 255 {
		return MdnsError{
			reason: .bad_name
			detail: 'the encoded name is ${w.buf.len} bytes, over the 255-byte limit'
		}
	}
	return w.buf
}

// answer_for pulls the address for name out of a response, if it is there.
//
// Anything unexpected returns none rather than an error: on a multicast group
// every response to every query on the network arrives here, and the ones that
// are not ours are the normal case, not a fault.
fn answer_for(datagram []u8, name string) ?netaddr.IpAddr {
	mut r := codec.Reader.new(datagram)
	_ := r.u16('transaction id') or { return none }
	flags := r.u16('flags') or { return none }
	// The response bit. A query looping back to us is not an answer.
	if flags & 0x8000 == 0 {
		return none
	}
	questions := r.u16('question count') or { return none }
	answers := r.u16('answer count') or { return none }
	_ := r.u16('authority count') or { return none }
	additional := r.u16('additional count') or { return none }

	for _ in 0 .. questions {
		skip_name(mut r) or { return none }
		r.u16('question type') or { return none }
		r.u16('question class') or { return none }
	}

	wanted := name.trim_right('.').to_lower()
	// Additional records are searched too: a responder often puts the AAAA
	// there when the question asked for an A.
	total := int(answers) + int(additional)
	for _ in 0 .. total {
		record_name := read_name(mut r) or { return none }
		record_type := r.u16('record type') or { return none }
		r.u16('record class') or { return none }
		r.u32('time to live') or { return none }
		length := r.u16('record length') or { return none }
		body := r.bytes(int(length), 'record data') or { return none }

		if record_name.trim_right('.').to_lower() != wanted {
			continue
		}
		if record_type == type_a && body.len == 4 {
			return netaddr.IpAddr.from_octets(.ipv4, body) or { continue }
		}
		if record_type == type_aaaa && body.len == 16 {
			return netaddr.IpAddr.from_octets(.ipv6, body) or { continue }
		}
	}
	return none
}