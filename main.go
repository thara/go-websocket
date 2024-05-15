package main

import (
	"crypto/sha1"
	"encoding/base64"
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	slog.Info("headers", slog.Any("protocols", r.Header))

	subprotocols := r.Header.Values("Sec-WebSocket-Protocol")
	if 0 < len(subprotocols) {
		w.Header().Set("Sec-WebSocket-Protocol", subprotocols[0])
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
}
