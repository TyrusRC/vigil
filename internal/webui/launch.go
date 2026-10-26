package webui

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const DefaultPort = 6274

// LaunchServer starts the web UI on the given port. Port 0 picks a free one.
func LaunchServer(handler http.Handler, port int) (net.Listener, string, error) {
	if port <= 0 {
		port = DefaultPort
	}
	// Bind IPv4 explicitly — "0.0.0.0" on WSL2 mirrored mode goes IPv6-only
	// which Windows localhost (127.0.0.1) can't reach. Use tcp4 to force IPv4.
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, "", fmt.Errorf("webui: port %d in use: %w", port, err)
	}
	// Addr().String() is "0.0.0.0:<port>" for a tcp4 wildcard bind, which a
	// browser (especially the Windows host browser over WSL2) cannot open.
	// Always hand back a loopback URL with the actually-bound port.
	actualPort := port
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		actualPort = tcp.Port
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)
	return ln, url, nil
}

// isWSL reports whether we're running inside Windows Subsystem for Linux.
func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	if b, err := os.ReadFile("/proc/version"); err == nil {
		v := strings.ToLower(string(b))
		return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
	}
	return false
}

// OpenBrowser opens the given URL in the default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		switch {
		case isWSL():
			// WSL2: hand the URL to the Windows host so it opens in the
			// Windows default browser. wslview (from wslu) is cleanest;
			// explorer.exe is always present as a fallback.
			if _, err := exec.LookPath("wslview"); err == nil {
				cmd = exec.Command("wslview", url)
			} else {
				cmd = exec.Command("explorer.exe", url)
			}
		default:
			if _, err := exec.LookPath("xdg-open"); err == nil {
				cmd = exec.Command("xdg-open", url)
			} else {
				cmd = exec.Command("sensible-browser", url)
			}
		}
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
