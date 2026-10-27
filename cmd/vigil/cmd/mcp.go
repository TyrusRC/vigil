package cmd

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TyrusRC/vigil/internal/api"
	"github.com/TyrusRC/vigil/internal/mcp"
)

var mcpStateFile string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run vigil as an MCP server over stdio (for AI agents)",
	Long: `Expose vigil's scan control surface as a Model Context Protocol server
over stdio, so an MCP-speaking agent that spawns "vigil mcp" can launch scans,
read findings and reports, and run compliance assessments.

The same tools are also served over HTTP at /mcp by "vigil web".

Examples:
  vigil mcp
  vigil mcp --state-file ~/.vigil/jobs.json`,
	Args: cobra.NoArgs,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().StringVar(&mcpStateFile, "state-file", "", "Persist scans/targets/settings to this JSON file (and its directory); shared with a running `vigil web` on the same file (default: in-memory only)")
}

func runMCP(cmd *cobra.Command, _ []string) error {
	// stdio is a local trust boundary (the agent spawned this process), so no
	// API key gates it; ToolsProvider still reports host tool availability.
	svc, err := buildAPIServer(scanRunner{}, mcpStateFile, api.ServerConfig{
		Version:       version,
		ToolsProvider: webTools,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[*] vigil MCP server on stdio")
	return mcp.New(svc, version).Run(cmd.Context(), &mcpsdk.StdioTransport{})
}

// mcpHTTPHandler serves the MCP streamable-HTTP endpoint, gated by the same API
// key as the REST API. The key may be a Bearer header or a ?key= query param.
func mcpHTTPHandler(svc *api.Server, apiKey string) http.Handler {
	h := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return mcp.New(svc, version)
	}, nil)
	if apiKey == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if len(got) > 7 && got[:7] == "Bearer " {
			got = got[7:]
		} else {
			got = r.URL.Query().Get("key")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(apiKey)) != 1 {
			http.Error(w, `{"error":"missing or invalid API key"}`, http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
