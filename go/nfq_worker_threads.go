//go:build workerthreads

package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
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

	// Enable NoENOBUFS option
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.Log("could not set NoENOBUFS option:", err)
		return
	}

	// Create a worker pool
	numWorkers := 4
	workChan := make(chan *nfqueue.Attribute, 1000) // Buffered channel
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attr := range workChan {
				id := *attr.PacketID
				logger.Log("Packet handled (ID: %d)\n", id)
				nf.SetVerdict(id, nfqueue.NfAccept)
			}
		}()
	}

	// Register the callback function
	fn := func(a nfqueue.Attribute) int {
		workChan <- &a
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
