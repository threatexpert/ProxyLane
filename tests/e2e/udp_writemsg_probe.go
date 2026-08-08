package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	targetFlag := flag.String("target", "203.0.113.10:39001", "UDP echo target")
	output := flag.String("output", "udp-writemsg-result.log", "result file")
	network := flag.String("network", "udp4", "udp or udp4")
	api := flag.String("api", "writemsg", "writemsg or writeto")
	flag.Parse()
	target, err := net.ResolveUDPAddr(*network, *targetFlag)
	diagnostic := ""
	if err == nil {
		var conn *net.UDPConn
		conn, err = net.ListenUDP(*network, &net.UDPAddr{IP: net.IPv4zero})
		if err == nil {
			defer conn.Close()
			diagnostic = fmt.Sprintf(" local=%s target=%s", conn.LocalAddr(), target)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("GO-UDP-WRITEMSG-PROBE")
			var sent int
			if *api == "writeto" {
				sent, err = conn.WriteToUDP(payload, target)
			} else {
				sent, _, err = conn.WriteMsgUDP(payload, nil, target)
			}
			if err == nil && sent != len(payload) {
				err = fmt.Errorf("short write: %d", sent)
			}
			if err == nil {
				reply := make([]byte, 256)
				var count int
				count, _, _, _, err = conn.ReadMsgUDP(reply, nil)
				if err == nil && string(reply[:count]) != string(payload) {
					err = fmt.Errorf("payload mismatch")
				}
			}
		}
	}
	result := "GO_UDP_PROBE_PASS" + diagnostic + "\n"
	if err != nil {
		result = "GO_UDP_PROBE_FAIL " + err.Error() + diagnostic + "\n"
	}
	_ = os.WriteFile(*output, []byte(result), 0o644)
	if err != nil {
		os.Exit(1)
	}
}
