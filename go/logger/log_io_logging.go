//go:build iologging
// +build iologging

package logger

func init() {
    SetIOMode(IOLogging)
}
