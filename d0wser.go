package main

import (
	"encoding/hex"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

/* Given the concatenation of the TCP pseudo-header and the TCP
segment (see RFC793) calculate the checksum that should be placed in
the TCP packet.  */
func get_tcp_checksum(data []byte) (checksum uint16) {
	var i int = 0
	var sum int = 0
	var size int = len(data)

	for size > 1 {
		sum += int(data[i])
		sum += int(data[i+1]) << 8
		i += 2
		size -= 2
	}

	if size == 1 {
		sum += int(data[i])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	// XXX bad code...
	tmp := uint16(^sum)
	checksum = (tmp & 0xff00) >> 8
	checksum += (tmp & 0xff) << 8
	return checksum
}

/** Return a closure that returns a new TCP port number everytime to
avoid collisions. DPI boxes don't like source port collisions. */
func get_next_source_port_n() func() int {
	rand.Seed(time.Now().UnixNano())
	i := int(rand.Int31n(28232) + 30000)
	return func() int { i++; return i }
}

var next_source_port_n func() int = get_next_source_port_n()

/* Return a TCP packet with payload 'data' to TCP port 'dst_port'. */
func form_tcp_packet(data []byte, dst_port uint16, conn *net.IPConn, ip string) (packet []byte) {
	const (
		SEQNUM uint32 = 0x1337;
		HDR_LENGTH uint8 = 20 / 4; // 20 bytes in 32-bit words
		WINDOW_SIZE uint16 = 512;
	)

	var SOURCE_PORT uint16 = uint16(next_source_port_n())
	var tcp_len int = len(data) + 20 // 20 bytes is the minimal TCP header

	/* Create the 'pseudo_header' for the calculation of TCP checksums. */
	pseudo_header := make([]byte, 12)
	copy(pseudo_header[0:4], net.ParseIP(conn.LocalAddr().String()).To4())
	if conn.RemoteAddr() != nil {
		copy(pseudo_header[4:8], net.ParseIP(conn.RemoteAddr().String()).To4())
	} else {
		copy(pseudo_header[4:8], net.ParseIP(ip).To4())
	}
	pseudo_header[8] = 0 // reserved
	pseudo_header[9] = 6 // protocol (TCP)
	binary.BigEndian.PutUint16(pseudo_header[10:], uint16(tcp_len))

	/* Create the actual TCP packet. */
	packet = make([]byte, tcp_len)
	binary.BigEndian.PutUint16(packet[0:], SOURCE_PORT)  /* src port */
	binary.BigEndian.PutUint16(packet[2:], dst_port)  /* dst port */
	binary.BigEndian.PutUint32(packet[4:], SEQNUM) /* seq num */
	binary.BigEndian.PutUint32(packet[8:], 0) /* ack num */
	packet[12] = 80                       /* header length */
	packet[13] = 16                       /* options */
	binary.BigEndian.PutUint16(packet[14:], WINDOW_SIZE) /* window size */
	binary.BigEndian.PutUint16(packet[16:], 0) /* checksum (will be filled later) */
	binary.BigEndian.PutUint16(packet[18:], 0) /* URG pointer */

	/* copy payload */
	copy(packet[20:20+len(data)], data)

	/* Merge the pseudoheader with the actual packet, to do the checksum calculation. */
	cksum_calculation_pkt := make([]byte, len(packet)+len(pseudo_header))
	copy(cksum_calculation_pkt, pseudo_header)
	copy(cksum_calculation_pkt[len(pseudo_header):], packet)
	var checksum uint16 = get_tcp_checksum(cksum_calculation_pkt)
	binary.BigEndian.PutUint16(packet[16:], checksum) /* put the new checksum */

	return packet
}

/* Send 'packet' to the connection 'conn' on TCP port 'port'. The
connection is not an established TCP connection, so we have to craft
the TCP headers on our own and send it through a raw socket. After
sending it, ask the user if he saw a sign of censorship in his packet
capturing software, and return back his result to the caller.

 XXX_1: No user interaction would be needed if Go had a libpcap wrapper.

 XXX_2: At the moment, the sign of censorship is whether we get an RST
 back from the host. In the future, we might find more of these quirks
 and have multiple oracles with different tests and behaviors.

 XXX_3: 'ip' is here because net.IPConn.RemoteAddr() seems to be
 broken (see issue 3721), and it's needed when calculating the TCP
 checksum.
*/
func query_oracle(payload []byte, port uint16, conn *net.IPConn, ip string) (reply bool) {
	/* Send the raw TCP packet. */
	packet := form_tcp_packet(payload, port, conn, ip)
	_, err := conn.Write(packet)
	if err != nil {
		panic(err)
	}

	time.Sleep(1.2 * 1e9)
	return false
}

/* Incrementally mutate 'censored_packet' and send it down to 'channel'. */
func mutate_packet(channel chan []byte, censored_packet []byte) {
	for i := range censored_packet {
		mutated_packet := make([]byte, len(censored_packet))
		copy(mutated_packet, censored_packet)
		mutated_packet[i] += 1

		fmt.Printf("Mutate byte '%d' (0x%x -> 0x%x):\n%s",
			i, censored_packet[i], mutated_packet[i], hex.Dump(mutated_packet))

		channel <- mutated_packet
	}
}

func usage() {
	fmt.Println("d0wser <censored packet> <oracle IP address> <oracle IP port>")
}

func main() {
	if len(os.Args) != 4 {
		usage()
		os.Exit(1)
	}

	packet_fname := os.Args[1]
	ip := os.Args[2]
	port_str := os.Args[3]

	port, err := strconv.ParseUint(port_str, 0, 16)
	if err != nil {
		panic(err)
	}

	addr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialIP("ip4:tcp", nil, addr) /* XXX no ipv6 */
	if err != nil {
		panic(err)
	}

	packet_contents, err := ioutil.ReadFile(packet_fname)
	if err != nil {
		panic(err)
	}

	/* Make a channel that generates and sends mutated packets. */
	packet_mutation_channel := make(chan []byte)
	go mutate_packet(packet_mutation_channel, packet_contents)

	/* Send the original censored packet: */
	/* query_oracle(packet_contents, uint16(port), conn, ip); */

	/* Incrementally mutate the original packet (by increasing each of
	   	 its bytes by one) and send it to the DPI box to see which
		 mutations bypassed its fingerprints. */
	for i := 0; i < len(packet_contents); i++ {
		var mutated_packet []byte = <-packet_mutation_channel

		query_oracle(mutated_packet, uint16(port), conn, ip)
	}
}
