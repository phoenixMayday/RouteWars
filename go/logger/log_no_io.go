//go:build noio
// +build noio

package logger

func init() {
    SetIOMode(NoIO)
}
