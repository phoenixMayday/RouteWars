package logger

import (
    "fmt"
    "os"
)

type IOMode int

const (
    NoIO IOMode = iota
    IOPrints
    IOLogging
)

var ioMode IOMode

func SetIOMode(mode IOMode) { // called by init() at comptime
    ioMode = mode
}

func Log(format string, args ...interface{}) {
    switch ioMode {
    case NoIO:
        // no I/O operations
    case IOPrints:
        // print to stdout
        fmt.Printf(format, args...)
    case IOLogging:
        // log to a file
        file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            fmt.Printf("Failed to open log file: %v\n", err)
            return
        }
        defer file.Close()
        fmt.Fprintf(file, format, args...)
    }
}
