// lulz dowser

package main

import (
		"fmt"
		"os"
		"io"
		"encoding/hex" // XXX debug
)

func usage() {
	fmt.Println("d0wser <censored packet> <oracle IP address> <oracle IP port>");
}

//var i int
//func mutate_packet_and_send(packet_channel chan []byte, packet []byte) {
//	
//	i = i + 1;
//	
//
//}
//

func query_oracle(next_packet []byte) (reply bool) {
	//send_raw_tcp_packet
	
	// ask the user if he saw the RST or whatever
	var user_reply string;
	for {
		println("Did you see the fnords? [y/n]");
		fmt.Scan(&user_reply);

		if (user_reply == "y") {
			return true;
		} else if (user_reply == "n") {
			return false;
		}
	}

	return false;
}
	

func main() {
	if (len(os.Args) != 4) {
		usage();
		os.Exit(1);
	}

	packet_fname := os.Args[1];
//	ip := os.Args[2];
//	addr := os.Args[3];

	f, err := os.Open(packet_fname);
	if err != nil { panic(err) }
	defer f.Close(); // ???

	packet_contents := make([]byte, 1600); // XXX static size
	n, err := f.Read(packet_contents);
    if err != nil && err != io.EOF { panic(err) }

//	packet_channel = make(chan []byte);

	var first_byte_of_fpr_found bool = false;
	var first_byte_of_fpr int = 0;
	var last_byte_of_fpr_found bool = false;
	var last_byte_of_fpr int = 0;

	for i := 0; i < n ; i++ {
		next_packet := make([]byte, n);
		copy(next_packet, packet_contents);
		next_packet[i] += 1;

		var oracle_reply bool = false;
		oracle_reply = query_oracle(next_packet);

		if (oracle_reply) {
			if (!first_byte_of_fpr_found) {
				first_byte_of_fpr_found = true;
				first_byte_of_fpr = i;
			} else {
				last_byte_of_fpr_found = true;
				last_byte_of_fpr = i;
			}
		}

		if first_byte_of_fpr_found == true && last_byte_of_fpr_found == true {
			break;
		}
		
		println(hex.Dump(next_packet));
	}

	println(string(first_byte_of_fpr), string(last_byte_of_fpr))

}
