// Package socks5 实现一个最小 SOCKS5 服务端, 只支持无认证 + CONNECT.
// 不依赖外部库, 协议见 RFC 1928. 每个连接用调用方传入的 DialFunc 拨号,
// 连接关闭时由 DialFunc 返回的 net.Conn 的 Close 负责释放底层资源.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialFunc 拨号到目标地址. 调用方在此获取 WARP 租约并穿透隧道,
// 返回的 net.Conn 关闭时应当释放租约.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Server 是一个 SOCKS5 服务端.
type Server struct {
	Dial       DialFunc
	Timeout    time.Duration
	BufferSize int
}

// Serve 接受一个已连接的客户端并处理一个 SOCKS5 会话.
func (s *Server) Serve(ctx context.Context, client net.Conn) error {
	defer client.Close()

	if s.Timeout > 0 {
		_ = client.SetDeadline(time.Now().Add(s.Timeout))
	}

	// 1. 握手: VER NMETHODS METHODS
	if err := s.negotiate(client); err != nil {
		return fmt.Errorf("socks5 negotiate: %w", err)
	}

	// 2. 请求: VER CMD RSV ATYP DST.ADDR DST.PORT
	addr, err := s.readRequest(client)
	if err != nil {
		return fmt.Errorf("socks5 request: %w", err)
	}

	_ = client.SetDeadline(time.Time{})

	// 3. 拨号
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()
	upstream, err := s.Dial(dialCtx, "tcp", addr)
	if err != nil {
		s.sendReply(client, 0x05) // Connection refused
		return fmt.Errorf("socks5 dial %s: %w", addr, err)
	}
	defer upstream.Close()

	// 4. 回复成功
	if err := s.sendReply(client, 0x00); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}

	// 5. 双向转发
	s.relay(client, upstream)
	return nil
}

func (s *Server) negotiate(client net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return errors.New("unsupported SOCKS version")
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		return errors.New("no auth methods offered")
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	// 选无认证 (0x00)
	_, err := client.Write([]byte{0x05, 0x00})
	return err
}

func (s *Server) readRequest(client net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 {
		return "", errors.New("unsupported SOCKS version in request")
	}
	if header[1] != 0x01 {
		return "", fmt.Errorf("unsupported command 0x%02x (only CONNECT)", header[1])
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return "", err
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("unsupported address type 0x%02x", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *Server) sendReply(client net.Conn, rep byte) error {
	// VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

type closeWriter interface {
	CloseWrite() error
}

func tryCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (s *Server) relay(client, upstream net.Conn) {
	bufSize := s.BufferSize
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.CopyBuffer(upstream, client, make([]byte, bufSize))
		tryCloseWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.CopyBuffer(client, upstream, make([]byte, bufSize))
		tryCloseWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (s *Server) dialTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Second
}
