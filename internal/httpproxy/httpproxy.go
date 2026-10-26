// Package httpproxy 实现一个最小 HTTP 正向代理: CONNECT 用于 HTTPS 隧道,
// absolute-URI 转发用于纯 HTTP 请求. 所有出站连接都走调用方提供的 DialFunc,
// 因此可以复用 SOCKS5 版本的 WARP 隧道池, 不需要 TUN 设备.
package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DialFunc 拨号到目标地址. 调用方在这里获取 WARP 租约并穿透隧道,
// 返回的 net.Conn 关闭时应当释放租约.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Server 是一个 HTTP 代理. Dial 必须设置, 其余字段可选.
type Server struct {
	Dial       DialFunc
	Timeout    time.Duration
	BufferSize int

	once      sync.Once
	transport *http.Transport
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ServeHTTP 实现 http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r)
		return
	}
	s.serveForward(w, r)
}

// serveConnect 处理 CONNECT: 先拨通目标, 再在客户端与目标之间原样转发字节.
// HTTPS 和大部分 WebSocket 客户端都走这条路径.
func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}

	upstream, err := s.dial(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// 客户端可能已经在 CONNECT 之后提前发送了 TLS ClientHello.
	if rw != nil {
		if n := rw.Reader.Buffered(); n > 0 {
			buffered, _ := rw.Reader.Peek(n)
			if _, err := upstream.Write(buffered); err != nil {
				return
			}
			_, _ = rw.Reader.Discard(n)
		}
	}
	relay(client, upstream, s.bufferSize())
}

// serveForward 处理纯 HTTP 代理请求. 客户端发来的是 absolute-URI,
// 这里用 http.Transport 转发, 并吞掉逐跳头.
func (s *Server) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "this is an HTTP proxy: use an absolute URI or CONNECT", http.StatusBadRequest)
		return
	}
	switch strings.ToLower(r.URL.Scheme) {
	case "http", "https":
	default:
		http.Error(w, "unsupported URL scheme", http.StatusBadRequest)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Close = false
	removeHopByHop(out.Header)

	resp, err := s.roundTripper().RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	dst := io.Writer(w)
	if flusher, ok := w.(http.Flusher); ok {
		dst = &flushWriter{w: w, f: flusher}
	}
	_, _ = io.CopyBuffer(dst, resp.Body, make([]byte, s.bufferSize()))
}

func (s *Server) roundTripper() http.RoundTripper {
	s.once.Do(func() {
		s.transport = &http.Transport{
			Proxy:               nil,
			DialContext:         s.dial,
			DisableCompression:  true,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 15 * time.Second,
		}
	})
	return s.transport
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHop(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, key := range hopHeaders {
		header.Del(key)
	}
}

type closeWriter interface {
	CloseWrite() error
}

func tryCloseWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func relay(client, upstream net.Conn, bufferSize int) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.CopyBuffer(upstream, client, make([]byte, bufferSize))
		tryCloseWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.CopyBuffer(client, upstream, make([]byte, bufferSize))
		tryCloseWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()
	return s.Dial(dialCtx, network, addr)
}

func (s *Server) bufferSize() int {
	if s.BufferSize > 0 {
		return s.BufferSize
	}
	return 32 * 1024
}

func (s *Server) dialTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Second
}
