package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/TyrusRC/vigil/internal/http"
)

// detectSPACatchAll sends requests to 3 random non-existent paths and compares
// response body hashes against the root page. If all return the same hash, the
// server has catch-all routing (typical of CDN-hosted SPAs like Lovable, Vercel,
// Netlify). Parameter-injection tests produce false positives on such targets
// because the server ignores all query parameters and path segments.
func detectSPACatchAll(ctx context.Context, client *http.Client, targetURL string) bool {
	probes := []string{
		"/vigil-spa-probe-a1b2c3d4",
		"/vigil-spa-probe-e5f6g7h8/nested/path",
		"/vigil-spa-probe-i9j0k1l2.nonexistent",
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rootResp, err := client.Get(probeCtx, targetURL)
	if err != nil || rootResp == nil || rootResp.StatusCode != 200 {
		return false
	}
	rootHash := bodyHash(rootResp.Body)
	if len(rootResp.Body) < 100 {
		return false // too short to be an SPA shell
	}

	matches := 0
	for _, probe := range probes {
		url := targetURL + probe
		resp, err := client.Get(probeCtx, url)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 && bodyHash(resp.Body) == rootHash {
			matches++
		}
	}

	return matches >= 2
}

func bodyHash(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%x", h[:8])
}
