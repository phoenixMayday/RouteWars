package main

import (
	"errors"
)

// decode QNAME from DNS packet.
func decodeQname(payload []byte, buffer []byte) ([]byte, error) {
	index := 12 // skip DNS header (12 bytes)
	bufferIndex := 0

	for {
		if index >= len(payload) {
			return nil, errors.New("invalid packet: out of bounds")
		}

		length := payload[index] // length of each label, e.g., [3]www[7]example[3]com[0]
		if length == 0 {
			break // end of QNAME
		}

		// Check if adding the length and '.' would exceed buffer size
		if bufferIndex+int(length)+1 > len(buffer) {
			return nil, errors.New("buffer overflow")
		}

		if bufferIndex > 0 {
			buffer[bufferIndex] = '.'
			bufferIndex++
		}
		index++

		for i := 0; i < int(length); i++ {
			buffer[bufferIndex] = payload[index]
			bufferIndex++
			index++
		}
	}

	return buffer[:bufferIndex], nil
}
