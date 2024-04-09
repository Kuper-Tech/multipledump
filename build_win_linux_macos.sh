#!/bin/bash

GOOS=windows GOARCH=amd64 go build -o multipleDump.exe multipleDump.go
GOOS=darwin GOARCH=amd64 go build -o multipleDump.bin.Macos multipleDump.go
GOOS=linux GOARCH=amd64 go build -o multipleDump.bin.Linux multipleDump.go