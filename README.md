# Go Sniffer

A simple network packet sniffer built with Golang.

## Project Structure

- `cmd/sniffer/` — Main entry point.
- `internal/capture/` — Packet capturing logic.
- `internal/parser/` — Packet parsing logic.
- `pkg/utils/` — Helper utilities.

## How to Run

```bash
go run cmd/sniffer/main.go
