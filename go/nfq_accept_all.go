//go:build acceptall

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
    "github.com/mdlayher/netlink"

    "nfq_go_router/logger"
)

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

    // Enable NoENOBUFS option -- get the error `netlink receive: recvmsg: no buffer space available` if not enabled
    if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
        logger.Log("could not set NoENOBUFS option:", err)
        return
    }

	// Register the callback function to handle/accept all packets
	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		logger.Log("Packet handled (ID: %d)\n", id)
		nf.SetVerdict(id, nfqueue.NfAccept) 
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
