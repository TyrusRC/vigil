package webui

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	switch runtime.GOOS {
	case "linux":
		if isWSL() {
			return openWSL(url)
		}
		return startFirst([][]string{{"xdg-open", url}, {"sensible-browser", url}})
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// openWSL opens the URL from a WSL session. The dashboard binds loopback, which
// a Linux (WSLg) browser can reach but the Windows host browser cannot — so
// when a GUI is present prefer a Linux browser, and fall back to launching the
// Windows host browser only when headless (no DISPLAY).
//
// For the Windows launchers, distros vary in what's reachable: some ship
// wslview (from wslu), and whether Windows dirs are on $PATH depends on
// interop/appendWindowsPath. So try each in turn — including explorer.exe /
// powershell.exe by absolute path, which the WSL interop layer still runs when
// they're off $PATH — and use the first that starts.
func openWSL(url string) error {
	var candidates [][]string
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		candidates = append(candidates,
			[]string{"xdg-open", url},
			[]string{"sensible-browser", url},
		)
	}
	candidates = append(candidates, []string{"wslview", url})
	candidates = append(candidates, []string{"explorer.exe", url})
	for _, exe := range windowsExes("Windows/explorer.exe") {
		candidates = append(candidates, []string{exe, url})
	}
	candidates = append(candidates, []string{"powershell.exe", "-NoProfile", "-Command", "Start-Process", url})
	for _, exe := range windowsExes("Windows/System32/WindowsPowerShell/v1.0/powershell.exe") {
		candidates = append(candidates, []string{exe, "-NoProfile", "-Command", "Start-Process", url})
	}
	candidates = append(candidates, []string{"cmd.exe", "/c", "start", "", url})
	return startFirst(candidates)
}

// windowsExes resolves a Windows-relative path (e.g. "Windows/explorer.exe")
// against the mounted Windows drives, returning the ones that exist.
func windowsExes(rel string) []string {
	var out []string
	roots, _ := filepath.Glob("/mnt/*/" + rel)
	for _, r := range roots {
		if st, err := os.Stat(r); err == nil && !st.IsDir() {
			out = append(out, r)
		}
	}
	return out
}

// startFirst starts the first candidate command that launches without error.
func startFirst(candidates [][]string) error {
	var lastErr error
	for _, c := range candidates {
		if len(c) == 0 {
			continue
		}
		if err := exec.Command(c[0], c[1:]...).Start(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no browser launcher available")
	}
	return lastErr
}
