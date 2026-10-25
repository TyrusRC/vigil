package webui

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
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
	url := "http://" + ln.Addr().String()
	return ln, url, nil
}

// OpenBrowser opens the given URL in the default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// WSL: try wslview first (opens in Windows browser), fall back to xdg-open
		if _, err := exec.LookPath("wslview"); err == nil {
			cmd = exec.Command("wslview", url)
		} else {
			cmd = exec.Command("xdg-open", url)
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
