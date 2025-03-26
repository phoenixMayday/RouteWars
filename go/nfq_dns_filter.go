//go:build dnsfilter

package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	"nfq_go_router/logger"
)

var nf *nfqueue.Nfqueue
var blocklist = []string{
    "example.com",
}
var ignoreDNSProbability = 0.95
var rng = rand.New(rand.NewSource(time.Now().UnixNano()))


func isBlocked(qname string) bool {
	for _, blocked := range blocklist {
		if qname == blocked || (len(qname) > len(blocked) && qname[len(qname)-len(blocked)-1:] == "."+blocked) {
			return true
		}
	}
	return false
}

func callback(a nfqueue.Attribute) int {
	// dereference packet info
	id := *a.PacketID
	payload := *a.Payload

	// payload[0] is a byte contains IP version and header length
	// the lower 4 bits (payload[0] & 0x0F) represent the number of 32-bit words in IP header
	// multiply by 4 (<< 2) to get length in bytes (32-bit words = 4 byte words)
	ipHeaderLen := int((payload[0] & 0x0F) << 2)

	// check if its a UDP DNS packet
	isMinUdpSize := len(payload) >= ipHeaderLen+8
	isUdp := payload[9] == 17
	if isMinUdpSize && isUdp {
		udpHeader := payload[ipHeaderLen : ipHeaderLen+8]
		dstPort := int(udpHeader[2])<<8 | int(udpHeader[3])

		// check if destination port is 53 (DNS)
		if dstPort == 53 {
			if rng.Float64() < ignoreDNSProbability {
				// Accept 95% of DNS packets without checking
				logger.Log("UDP DNS packet randomly accepted (ID: %d)\n", id)
				nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			dnsPayload := payload[ipHeaderLen+8:]
			// Decode the QNAME
			buffer := make([]byte, 256)
			qnameBytes, err := decodeQname(dnsPayload, buffer)
			if err != nil {
				logger.Log("Error decoding QNAME (ID: %d): %v\n", id, err)
				nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			qname := string(qnameBytes) // Convert []byte to string
			if isBlocked(qname) {
				logger.Log("UDP DNS packet blocked (ID: %d), Domain: %s\n", id, qname)
				nf.SetVerdict(id, nfqueue.NfDrop)
				return 0
			}

			logger.Log("UDP DNS packet accepted (ID: %d), Domain: %s\n", id, qname)
		}
	} else {
		logger.Log("Data packet handled (ID: %d)\n", id)
	}

	// Accept all other packets
	nf.SetVerdict(id, nfqueue.NfAccept)
	return 0
}

func main() {
	config := nfqueue.Config{
		NfQueue:      0,                       // Queue number
		MaxPacketLen: 0xFFFF,                  // Maximum packet length
		MaxQueueLen:  0xFFFF,                  // Maximum queue length
		Copymode:     nfqueue.NfQnlCopyPacket, // Copy packet data to userspace
		WriteTimeout: 15 * time.Millisecond,
	}

	// Open nfq
	var err error
	nf, err = nfqueue.Open(&config)
	if err != nil {
		logger.Log("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	// Enable NoENOBUFS option -- get the error `netlink receive: recvmsg: no buffer space available` if not enabled
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.Log("could not set NoENOBUFS option:", err)
		return
	}

	// Register callback with an error handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = nf.RegisterWithErrorFunc(ctx, callback, func(e error) int {
		logger.Log("Error:", e)
		return -1
	})
	if err != nil {
		logger.Log("failed to register callback:", err)
		return
	}

	// Set up signal handler to gracefully exit on interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Log("Received interrupt signal, shutting down...")
		cancel()
	}()

	<-ctx.Done()
	logger.Log("Exiting...")
}

