package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"
)

func main() {
	s := &http.Server{
		Addr:         ":8080",
		Handler:      logging(http.HandlerFunc(handler)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}

func logging(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request", "method", r.Method, "url", r.URL.String())
		h.ServeHTTP(w, r)
	})
}

const acceptMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" && r.Header.Get("Connection") != "Upgrade" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	slog.Info("headers", slog.Any("protocols", r.Header))

	subprotocols := r.Header.Values("Sec-WebSocket-Protocol")
	if 0 < len(subprotocols) {
		w.Header().Set("Sec-WebSocket-Protocol", subprotocols[0])
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	key += acceptMagicGUID

	h := sha1.New()
	io.WriteString(h, key)
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", accept)

	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, buf, err := hj.Hijack()
	if err != nil {
		slog.Debug("hijack failed", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	f, err := parseFrame(buf.Reader)
	if err != nil {
		slog.Debug("parseFrame failed", slog.Any("error", err))
	} else {
		fmt.Printf("frame: %+v\n", f)
	}
}

type opcode uint8

const (
	opcodeContinuation opcode = 0x00
	opcodeText         opcode = 0x01
	opcodeBinary       opcode = 0x02
	opcodeClose        opcode = 0x08
	opcodePing         opcode = 0x09
	opcodePong         opcode = 0x0A
)

type frame struct {
	final   bool
	opcode  opcode
	length  uint64
	payload []byte
}

func parseFrame(buf *bufio.Reader) (frame, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return frame{}, fmt.Errorf("read failed: %w", err)
	}
	fin := b & 0x80
	op := opcode(b & 0x0F)

	b, err = buf.ReadByte()
	if err != nil {
		return frame{}, fmt.Errorf("read failed: %w", err)
	}
	mask := b & 0x80
	length := uint64(b & 0x7F)

	if length == 126 {
		var b [2]byte
		if n, err := buf.Read(b[:]); err != nil {
			return frame{}, fmt.Errorf("read failed: %w", err)
		} else if n != 2 {
			return frame{}, fmt.Errorf("read failed: expected 2 bytes, got %d", n)
		}
		length = binary.BigEndian.Uint64(b[:])
	} else if length == 127 {
		var b [8]byte
		if n, err := buf.Read(b[:]); err != nil {
			return frame{}, fmt.Errorf("read failed: %w", err)
		} else if n != 8 {
			return frame{}, fmt.Errorf("read failed: expected 8 bytes, got %d", n)
		}
		length = binary.BigEndian.Uint64(b[:])
	}

	var maskingKey []byte
	if mask == 0x80 {
		maskingKey = make([]byte, 4)
		if n, err := buf.Read(maskingKey); err != nil {
			return frame{}, fmt.Errorf("read failed: %w", err)
		} else if n != 4 {
			return frame{}, fmt.Errorf("read failed: expected 4 bytes, got %d", n)
		}
	}

	payload := make([]byte, length)
	if n, err := buf.Read(payload); err != nil {
		return frame{}, fmt.Errorf("read failed: %w", err)
	} else if n != int(length) {
		return frame{}, fmt.Errorf("read failed: expected %d bytes, got %d", length, n)
	}

	f := frame{
		final:   fin == 0x80,
		opcode:  op,
		length:  length,
		payload: payload,
	}

	return f, nil
}
