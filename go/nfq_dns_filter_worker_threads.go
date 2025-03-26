//go:build dnsfilterworkerthreads

package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	"nfq_go_router/logger"
)

var	blocklist = []string{
	"example.com",
}
var	ignoreDNSProbability = 0.95
var	rng = rand.New(rand.NewSource(time.Now().UnixNano()))

type packetJob struct {
	attr  *nfqueue.Attribute
	nfq   *nfqueue.Nfqueue
}

func isBlocked(qname string) bool {
	for _, blocked := range blocklist {
		if qname == blocked || (len(qname) > len(blocked) && qname[len(qname)-len(blocked)-1:] == "."+blocked) {
			return true
		}
	}
	return false
}

func processPacket(job packetJob) {
	// dereference packet info
	id := *job.attr.PacketID
	payload := *job.attr.Payload

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
				job.nfq.SetVerdict(id, nfqueue.NfAccept)
				return
			}

			dnsPayload := payload[ipHeaderLen+8:]
			// Decode the QNAME
			buffer := make([]byte, 256)
			qnameBytes, err := decodeQname(dnsPayload, buffer)
			if err != nil {
				logger.Log("Error decoding QNAME (ID: %d): %v\n", id, err)
				job.nfq.SetVerdict(id, nfqueue.NfAccept)
				return
			}

			qname := string(qnameBytes) // Convert []byte to string
			if isBlocked(qname) {
				logger.Log("UDP DNS packet blocked (ID: %d), Domain: %s\n", id, qname)
				job.nfq.SetVerdict(id, nfqueue.NfDrop)
				return
			}

			logger.Log("UDP DNS packet accepted (ID: %d), Domain: %s\n", id, qname)
		}
	} else {
		logger.Log("Data packet handled (ID: %d)\n", id)
	}

	// Accept all other packets
	job.nfq.SetVerdict(id, nfqueue.NfAccept)
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
	nf, err := nfqueue.Open(&config)
	if err != nil {
		logger.Log("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	// Enable NoENOBUFS option
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.Log("could not set NoENOBUFS option:", err)
		return
    }:q

	// Create a worker pool
	numWorkers := 4
	workChan := make(chan packetJob, 1000) // Buffered channel
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range workChan {
				processPacket(job)
			}
		}()
	}

	// Register the callback function
	fn := func(a nfqueue.Attribute) int {
		workChan <- packetJob{attr: &a, nfq: nf}
		return 0
	}

	// Register callback with an error handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		logger.Log("Error:", e)
		return -1
	})
	if err != nil {
		logger.Log("failed to register callback:", err)
		return
	}

	// Set up signal handler to gracefully exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Log("Received interrupt signal, shutting down...")
		cancel()
		close(workChan) // Close channel to terminate workers
	}()

	<-ctx.Done()
	wg.Wait()
	logger.Log("Exiting...")
}
