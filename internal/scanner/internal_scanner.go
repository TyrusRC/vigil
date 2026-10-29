package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/detection/adminpath"
	"github.com/TyrusRC/vigil/internal/iast"
	// blank line kept so the import block is not one giant line

	"github.com/TyrusRC/vigil/internal/detection/apispec"
	"github.com/TyrusRC/vigil/internal/detection/apiversion"
	"github.com/TyrusRC/vigil/internal/detection/auth"
	"github.com/TyrusRC/vigil/internal/detection/authbypass403"
	"github.com/TyrusRC/vigil/internal/detection/behavior"
	"github.com/TyrusRC/vigil/internal/detection/cachedeception"
	"github.com/TyrusRC/vigil/internal/detection/cachekey"
	"github.com/TyrusRC/vigil/internal/detection/cachepoisoning"
	"github.com/TyrusRC/vigil/internal/detection/cloud"
	"github.com/TyrusRC/vigil/internal/detection/cmdi"
	"github.com/TyrusRC/vigil/internal/detection/contenttype"
	"github.com/TyrusRC/vigil/internal/detection/cors"
	"github.com/TyrusRC/vigil/internal/detection/crlf"
	"github.com/TyrusRC/vigil/internal/detection/cspt"
	"github.com/TyrusRC/vigil/internal/detection/csrf"
	"github.com/TyrusRC/vigil/internal/detection/cssinj"
	"github.com/TyrusRC/vigil/internal/detection/csti"
	"github.com/TyrusRC/vigil/internal/detection/csvinj"
	"github.com/TyrusRC/vigil/internal/detection/dataexposure"
	"github.com/TyrusRC/vigil/internal/detection/depconfusion"
	"github.com/TyrusRC/vigil/internal/detection/deser"
	"github.com/TyrusRC/vigil/internal/detection/dnsrebinding"
	"github.com/TyrusRC/vigil/internal/detection/domclobber"
	"github.com/TyrusRC/vigil/internal/detection/emailinj"
	"github.com/TyrusRC/vigil/internal/detection/exposure"
	"github.com/TyrusRC/vigil/internal/detection/fileupload"
	"github.com/TyrusRC/vigil/internal/detection/graphql"
	"github.com/TyrusRC/vigil/internal/detection/graphqladvanced"
	"github.com/TyrusRC/vigil/internal/detection/graphqldos"
	"github.com/TyrusRC/vigil/internal/detection/grpcreflect"
	"github.com/TyrusRC/vigil/internal/detection/h2reset"
	"github.com/TyrusRC/vigil/internal/detection/headerinj"
	"github.com/TyrusRC/vigil/internal/detection/hosthdr"
	"github.com/TyrusRC/vigil/internal/detection/hpp"
	"github.com/TyrusRC/vigil/internal/detection/htmlinj"
	"github.com/TyrusRC/vigil/internal/detection/http2advanced"
	"github.com/TyrusRC/vigil/internal/detection/http2desync"
	"github.com/TyrusRC/vigil/internal/detection/http2race"
	"github.com/TyrusRC/vigil/internal/detection/idor"
	"github.com/TyrusRC/vigil/internal/detection/injection"
	"github.com/TyrusRC/vigil/internal/detection/jkuabuse"
	"github.com/TyrusRC/vigil/internal/detection/jndi"
	"github.com/TyrusRC/vigil/internal/detection/jsdep"
	"github.com/TyrusRC/vigil/internal/detection/jwt"
	"github.com/TyrusRC/vigil/internal/detection/jwtadvanced"
	"github.com/TyrusRC/vigil/internal/detection/ldap"
	"github.com/TyrusRC/vigil/internal/detection/lfi"
	"github.com/TyrusRC/vigil/internal/detection/loginj"
	"github.com/TyrusRC/vigil/internal/detection/massassign"
	"github.com/TyrusRC/vigil/internal/detection/mfabypass"
	"github.com/TyrusRC/vigil/internal/detection/nosql"
	"github.com/TyrusRC/vigil/internal/detection/oauth"
	"github.com/TyrusRC/vigil/internal/detection/oauthflow"
	"github.com/TyrusRC/vigil/internal/detection/oob"
	"github.com/TyrusRC/vigil/internal/detection/openapisemantic"
	"github.com/TyrusRC/vigil/internal/detection/ormleak"
	"github.com/TyrusRC/vigil/internal/detection/paddingoracle"
	"github.com/TyrusRC/vigil/internal/detection/passwordreset"
	"github.com/TyrusRC/vigil/internal/detection/pathnorm"
	"github.com/TyrusRC/vigil/internal/detection/postmsg"
	"github.com/TyrusRC/vigil/internal/detection/promptinjection"
	"github.com/TyrusRC/vigil/internal/detection/protopollution"
	"github.com/TyrusRC/vigil/internal/detection/racecond"
	"github.com/TyrusRC/vigil/internal/detection/ratelimit"
	"github.com/TyrusRC/vigil/internal/detection/redirect"
	"github.com/TyrusRC/vigil/internal/detection/redos"
	"github.com/TyrusRC/vigil/internal/detection/rfi"
	"github.com/TyrusRC/vigil/internal/detection/samesitelax"
	"github.com/TyrusRC/vigil/internal/detection/cookietoss"
	"github.com/TyrusRC/vigil/internal/detection/cspaudit"
	"github.com/TyrusRC/vigil/internal/detection/iistilde"
	"github.com/TyrusRC/vigil/internal/detection/webhooksig"

	"github.com/TyrusRC/vigil/internal/detection/apioverexpose"
	"github.com/TyrusRC/vigil/internal/detection/openapiexpose"
	"github.com/TyrusRC/vigil/internal/detection/typeconfuse"
	"github.com/TyrusRC/vigil/internal/detection/longpwd"
	"github.com/TyrusRC/vigil/internal/detection/samesitescript"
	"github.com/TyrusRC/vigil/internal/detection/wafdetect"
	"github.com/TyrusRC/vigil/internal/detection/xfs"
	"github.com/TyrusRC/vigil/internal/payloads/arginject"
	"github.com/TyrusRC/vigil/internal/payloads/esi"
	"github.com/TyrusRC/vigil/internal/payloads/fileops"
	"github.com/TyrusRC/vigil/internal/payloads/http3desync"
	"github.com/TyrusRC/vigil/internal/payloads/javareflect"
	"github.com/TyrusRC/vigil/internal/payloads/nodejsinject"
	"github.com/TyrusRC/vigil/internal/payloads/paraminject"
	"github.com/TyrusRC/vigil/internal/payloads/phpinject"
	"github.com/TyrusRC/vigil/internal/payloads/rscinject"
	"github.com/TyrusRC/vigil/internal/payloads/solrinject"
	"github.com/TyrusRC/vigil/internal/payloads/webauthn"
	"github.com/TyrusRC/vigil/internal/payloads/vhost"
	"github.com/TyrusRC/vigil/internal/detection/samlinj"
	"github.com/TyrusRC/vigil/internal/detection/secheaders"
	"github.com/TyrusRC/vigil/internal/detection/secondorder"
	"github.com/TyrusRC/vigil/internal/detection/sessionfixation"
	"github.com/TyrusRC/vigil/internal/detection/sessionlifecycle"
	"github.com/TyrusRC/vigil/internal/detection/smuggling"
	"github.com/TyrusRC/vigil/internal/detection/sse"
	"github.com/TyrusRC/vigil/internal/detection/ssi"
	"github.com/TyrusRC/vigil/internal/detection/ssrf"
	"github.com/TyrusRC/vigil/internal/detection/ssti"
	"github.com/TyrusRC/vigil/internal/detection/stacktrace"
	"github.com/TyrusRC/vigil/internal/detection/storage"
	"github.com/TyrusRC/vigil/internal/detection/storageinj"
	"github.com/TyrusRC/vigil/internal/detection/subtakeover"
	"github.com/TyrusRC/vigil/internal/detection/tabnabbing"
	"github.com/TyrusRC/vigil/internal/detection/techstack"
	tlsdetect "github.com/TyrusRC/vigil/internal/detection/tls"
	"github.com/TyrusRC/vigil/internal/detection/tokenentropy"
	"github.com/TyrusRC/vigil/internal/detection/typejuggling"
	"github.com/TyrusRC/vigil/internal/detection/verbtamper"
	"github.com/TyrusRC/vigil/internal/detection/ws"
	"github.com/TyrusRC/vigil/internal/detection/xpath"
	"github.com/TyrusRC/vigil/internal/detection/xsleaks"
	"github.com/TyrusRC/vigil/internal/detection/xslt"
	"github.com/TyrusRC/vigil/internal/detection/xss"
	"github.com/TyrusRC/vigil/internal/detection/xxe"
	"github.com/TyrusRC/vigil/internal/discovery"
	"github.com/TyrusRC/vigil/internal/headless"
	"github.com/TyrusRC/vigil/internal/http"
)

// TechHint captures technology names detected during scanning.
type TechHint struct {
	Technologies   []string // lowercase normalized names
	LFIWrappers    bool     // PHP wrappers (php://, phar://)
	JavaDeser      bool     // Java deserialization
	NodeProto      bool     // Prototype pollution
	TemplateEngine string   // Detected template engine name
}

// InternalScanner provides built-in vulnerability detection capabilities.
// It complements external tools by providing detection for common vulnerabilities
// using the internal detection modules.
type InternalScanner struct {
	client                 *http.Client
	sqliDetector           *injection.SQLiDetector
	xssDetector            *xss.Detector
	cmdiDetector           *cmdi.Detector
	ssrfDetector           *ssrf.Detector
	lfiDetector            *lfi.Detector
	xxeDetector            *xxe.Detector
	techDetector           *techstack.Detector
	nosqlDetector          *nosql.Detector
	sstiDetector           *ssti.Detector
	idorDetector           *idor.Detector
	jwtDetector            *jwt.Detector
	redirectDetector       *redirect.Detector
	corsDetector           *cors.Detector
	crlfDetector           *crlf.Detector
	ldapDetector           *ldap.Detector
	xpathDetector          *xpath.Detector
	headerInjDetector      *headerinj.Detector
	cstiDetector           *csti.Detector
	rfiDetector            *rfi.Detector
	jndiDetector           *jndi.Detector
	secHeadersDetector     *secheaders.Detector
	exposureDetector       *exposure.Detector
	cloudDetector          *cloud.Detector
	subTakeoverDetector    *subtakeover.Detector
	tlsAnalyzer            *tlsdetect.Analyzer
	authDetector           *auth.Detector
	graphqlDetector        *graphql.Detector
	smugglingDetector      *smuggling.Detector
	behaviorDetector       *behavior.Detector
	storageInjDetector     *storageinj.Detector
	logInjDetector         *loginj.Detector
	fileUploadDetector     *fileupload.Detector
	verbTamperDetector     *verbtamper.Detector
	pathNormDetector       *pathnorm.Detector
	raceCondDetector       *racecond.Detector
	csvInjDetector         *csvinj.Detector
	wsDetector             *ws.Detector
	hostHdrDetector        *hosthdr.Detector
	oauthDetector          *oauth.Detector
	jsdepDetector          *jsdep.Detector
	dataExposureDetector   *dataexposure.Detector
	adminPathDetector      *adminpath.Detector
	apiVersionDetector     *apiversion.Detector
	rateLimitDetector      *ratelimit.Detector
	apiSpecRunner          *apispec.Runner
	contentTypeDetector    *contenttype.Detector
	sseDetector            *sse.Detector
	grpcReflectDetector    *grpcreflect.Detector
	h2ResetDetector        *h2reset.Detector
	csrfDetector           *csrf.Detector
	tabnabbingDetector     *tabnabbing.Detector
	csptDetector           *cspt.Detector
	redosDetector          *redos.Detector
	promptInjDetector      *promptinjection.Detector
	xsltDetector           *xslt.Detector
	samlInjDetector        *samlinj.Detector
	ormLeakDetector        *ormleak.Detector
	typeJugglingDetector   *typejuggling.Detector
	depConfusionDetector   *depconfusion.Detector
	tokenEntropyDetector   *tokenentropy.Detector
	cacheDeceptionDetector *cachedeception.Detector
	cachePoisoningDetector *cachepoisoning.Detector
	cssInjDetector         *cssinj.Detector
	deserDetector          *deser.Detector
	domClobberDetector     *domclobber.Detector
	emailInjDetector       *emailinj.Detector
	hppDetector            *hpp.Detector
	htmlInjDetector        *htmlinj.Detector
	massAssignDetector     *massassign.Detector
	protoPollutionDetector *protopollution.Detector
	secondOrderDetector    *secondorder.Detector
	storedXSSDetector      *xss.StoredDetector
	ssiDetector            *ssi.Detector
	storageDetector        *storage.Detector
	postMsgDetector        *postmsg.Detector
	// Wave-G — stateful auth flow detectors (default-on but URL-gated)
	passwordResetDetector    *passwordreset.Detector
	sessionLifecycleDetector *sessionlifecycle.Detector
	oauthFlowDetector        *oauthflow.Detector
	dnsRebindingDetector     *dnsrebinding.Detector
	openAPISemanticDetector  *openapisemantic.Detector
	http2AdvancedDetector    *http2advanced.Detector
	// Wave-H — coverage gaps from OWASP API/Top10/WSTG mapping audit
	sessionFixationDetector *sessionfixation.Detector
	stackTraceDetector      *stacktrace.Detector
	mfaBypassDetector       *mfabypass.Detector
	paddingOracleDetector   *paddingoracle.Detector
	xsleaksDetector         *xsleaks.Detector
	jwtAdvancedDetector     *jwtadvanced.Detector
	graphqlAdvancedDetector *graphqladvanced.Detector
	http2DesyncDetector     *http2desync.Detector
	cachekeyDetector        *cachekey.Detector
	authBypass403Detector   *authbypass403.Detector
	http2RaceDetector       *http2race.Detector
	graphqlDosDetector      *graphqldos.Detector
	jkuAbuseDetector        *jkuabuse.Detector
	sameSiteLaxDetector     *samesitelax.Detector
	wafDetector             *wafdetect.Detector
	xfsDetector             *xfs.Detector
	iisTildeDetector        *iistilde.Detector
	sameSiteScriptDetector  *samesitescript.Detector
	longPwdDetector         *longpwd.Detector
	vhostDetector           *vhost.Detector
	esiDetector             *esi.Detector
	solrInjectDetector      *solrinject.Detector
	phpInjectDetector       *phpinject.Detector
	javaReflectDetector     *javareflect.Detector
	nodejsInjectDetector    *nodejsinject.Detector
	argInjectDetector       *arginject.Detector
	fileOpsDetector         *fileops.Detector
	rscInjectDetector       *rscinject.Detector
	webauthnDetector        *webauthn.Detector
	http3DesyncDetector     *http3desync.Detector
	cspAuditDetector        *cspaudit.Detector
	cookieTossDetector      *cookietoss.Detector
	webhookSigDetector      *webhooksig.Detector
	typeConfuseDetector     *typeconfuse.Detector
	apiOverexposeDetector   *apioverexpose.Detector
	openapiExposeDetector   *openapiexpose.Detector
	discoveryPipeline       *discovery.Pipeline
	headlessPool            *headless.Pool
	oobClient               *oob.Client
	oobReady                chan struct{} // signals when OOB client is ready
	oobInitErr              error         // error from OOB initialization
	techHint                *TechHint
	config                  *InternalScanConfig
	confirmed               *confirmedFindings
	// baselineCache is the per-scan shared baseline cache consumed by the
	// 7 bank-driven parameter-injection detectors (esi, solrinject,
	// phpinject, javareflect, arginject, fileops + esi). Reset at the
	// start of every Scan call; nil is safe (detectors fall through to
	// uncached fetch).
	baselineCache *paraminject.Cache
	iastServer      *iast.Server
	coverageTracker *CoverageTracker
	mu              sync.Mutex

	// Fields populated during Scan for the smart tool dispatcher.
	Technologies        []string
	discoveredURLs      []string
	injectionCandidates []InjectionCandidate
}

// InjectionCandidate records a parameter where the native detector
// found or suspected a vulnerability. The smart tool dispatcher uses
// these to launch focused sqlmap/dalfox/commix runs on the exact
// param instead of crawling the whole site.
type InjectionCandidate struct {
	URL       string
	Parameter string
	Method    string
	Location  string
	VulnClass string
	Evidence  string
	DBMS      string // database type if detected (PostgreSQL, MySQL, etc.)
}

// recordInjectionCandidate appends a candidate from a confirmed native
// detector finding. Thread-safe.
func (s *InternalScanner) recordInjectionCandidate(targetURL string, param core.Parameter, method, vulnClass string, finding *core.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evidence := ""
	dbms := ""
	if finding != nil {
		evidence = finding.Evidence
		// Extract DBMS hint from finding description/evidence for sqlmap
		desc := strings.ToLower(finding.Description + " " + finding.Evidence)
		switch {
		case strings.Contains(desc, "postgresql") || strings.Contains(desc, "pg_"):
			dbms = "PostgreSQL"
		case strings.Contains(desc, "mysql") || strings.Contains(desc, "mariadb"):
			dbms = "MySQL"
		case strings.Contains(desc, "mssql") || strings.Contains(desc, "microsoft sql"):
			dbms = "MSSQL"
		case strings.Contains(desc, "oracle") || strings.Contains(desc, "ora-"):
			dbms = "Oracle"
		case strings.Contains(desc, "sqlite"):
			dbms = "SQLite"
		}
	}
	s.injectionCandidates = append(s.injectionCandidates, InjectionCandidate{
		URL:       targetURL,
		Parameter: param.Name,
		Method:    method,
		Location:  param.Location,
		VulnClass: vulnClass,
		Evidence:  evidence,
		DBMS:      dbms,
	})
}

// NewInternalScanner creates a new internal scanner. The constructor
// instantiates every detector eagerly and brings up the discovery
// pipeline / headless pool when their feature flags request them. OOB
// initialization is deferred to scan time (startOOBClientAsync) so the
// constructor never blocks on network.
func NewInternalScanner(config *InternalScanConfig) (*InternalScanner, error) {
	if config == nil {
		config = DefaultInternalConfig()
	}

	httpClient := http.NewClient().WithTimeout(config.RequestTimeout)
	if config.Scope != nil {
		httpClient = httpClient.WithScope(config.Scope)
	}
	if config.RateLimitPerSec > 0 {
		httpClient = httpClient.WithRateLimit(config.RateLimitPerSec)
	}
	if config.Session != nil {
		httpClient = httpClient.WithCookieSource(config.Session.Cookie)
	}

	techDetector, techErr := techstack.NewDetector()
	if techErr != nil && config.Verbose {
		fmt.Fprintf(os.Stderr, "[!] Tech stack detection unavailable: %v\n", techErr)
	}

	scanner := &InternalScanner{
		coverageTracker: NewCoverageTracker(),
	}
	scanner.initDetectors(httpClient, config, techDetector)

	if config.EnableDiscovery {
		scanner.initDiscovery(httpClient)
	}
	if config.needsHeadless() {
		scanner.initHeadless(config)
	}
	// OOB client will be initialized lazily during scan if needed
	// (startOOBClientAsync); this prevents blocking scanner creation.
	return scanner, nil
}

// Close releases resources. Safe to call multiple times.
func (s *InternalScanner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.oobClient != nil {
		s.oobClient.Close()
		s.oobClient = nil
	}
	if s.headlessPool != nil {
		s.headlessPool.Close()
		s.headlessPool = nil
	}
}

// CoverageData returns the coverage tracker for external consumption.
func (s *InternalScanner) CoverageData() *CoverageTracker {
	return s.coverageTracker
}

// InternalScanResult contains results from internal scanning.
type InternalScanResult struct {
	Findings     core.Findings
	Technologies *techstack.DetectionResult
	Errors       []string
}

// applyScanConfigInPlace applies per-scan transport settings to the client
// in place. All detectors hold a reference to this same client object, so
// mutating it propagates proxy/headers/cookies/UA to every detector.
// One-Scanner-per-Scan is the contract.
func applyScanConfigInPlace(client *http.Client, cfg *Config) {
	if client == nil || cfg == nil {
		return
	}
	if len(cfg.Headers) > 0 {
		client.WithHeaders(cfg.Headers)
	}
	if cfg.Cookies != "" {
		client.WithCookies(cfg.Cookies)
	}
	if cfg.UserAgent != "" {
		client.WithUserAgent(cfg.UserAgent)
	}
	if cfg.ProxyURL != "" {
		client.WithProxy(cfg.ProxyURL)
	}
	if cfg.Insecure {
		client.WithInsecure(true)
	}
}
