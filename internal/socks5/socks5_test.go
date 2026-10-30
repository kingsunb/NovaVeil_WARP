package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNegotiateUserPass(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	result := make(chan struct {
		username string
		err      error
	}, 1)
	go func() {
		srv := &Server{}
		username, err := srv.negotiate(server)
		result <- struct {
			username string
			err      error
		}{username: username, err: err}
	}()

	if _, err := client.Write([]byte{0x05, 2, 0x00, 0x02}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("method reply = %v, want [5 2]", reply)
	}

	if _, err := client.Write([]byte{0x01, 6, 'w', 'a', 'r', 'p', '-', '1', 0x00}); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(client, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 0x01 || auth[1] != 0x00 {
		t.Fatalf("auth reply = %v, want [1 0]", auth)
	}

	got := <-result
	if got.err != nil {
		t.Fatalf("negotiate error = %v", got.err)
	}
	if got.username != "warp-1" {
		t.Fatalf("username = %q, want warp-1", got.username)
	}
}

func TestNegotiateNoAuthFallback(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	result := make(chan error, 1)
	go func() {
		srv := &Server{}
		_, err := srv.negotiate(server)
		result <- err
	}()

	if _, err := client.Write([]byte{0x05, 1, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("method reply = %v, want [5 0]", reply)
	}
	if err := <-result; err != nil {
		t.Fatalf("negotiate error = %v", err)
	}
}

type testReplyError struct {
	reply byte
}

func (e testReplyError) Error() string { return "test reply error" }

func (e testReplyError) Socks5Reply() byte { return e.reply }

func TestSocksReply(t *testing.T) {
	if got := socksReply(testReplyError{reply: 0x02}); got != 0x02 {
		t.Fatalf("socksReply = %#x, want 0x02", got)
	}
	if got := socksReply(io.EOF); got != 0x05 {
		t.Fatalf("default socksReply = %#x, want 0x05", got)
	}
}
