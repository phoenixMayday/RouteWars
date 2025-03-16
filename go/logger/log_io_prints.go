//go:build ioprints
// +build ioprints

package logger

func init() {
    SetIOMode(IOPrints)
}
