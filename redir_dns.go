package redirdns

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	// Default DNS TXT record prefix
	defaultDnsPrefix = "_redirdns"

	// Default HTTP response status code
	defaultStatusCode = 302

	// Default HTTP response template
	defaultResponseTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{.Title}}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="font-family:sans-serif;text-align:center;padding-top:10vh;">
  <h1>{{.Title}}</h1>
  <p>{{.Msg}}</p>
</body>
</html>`
)

func init() {
	caddy.RegisterModule(RedirDns{})
	httpcaddyfile.RegisterHandlerDirective("redir_dns", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redir_dns", httpcaddyfile.After, "redir")
}

// RedirDns is a Caddy module implementing HTTP redirects stored in DNS TXT records
type RedirDns struct {
	// The target URL to redirect when an error occurs. Default: none
	DefaultTarget string `json:"default_target,omitempty"`
	// DNS TXT record prefix where the redirect information is stored. Default: "_redirdns"
	DnsPrefix string `json:"dns_prefix,omitempty"`
	// The HTTP status code returned by the redirect response. Default: 302
	StatusCode int `json:"status_code,omitempty"`
	// The HTML response document served when the redirect cannot be completed
	responseTpl *template.Template
	logger      *zap.Logger
	replacer    *strings.Replacer
}

func New() *RedirDns {
	// create and return new RedirDns struct with default values
	rd := RedirDns{
		DefaultTarget: "",
		DnsPrefix:     defaultDnsPrefix,
		StatusCode:    defaultStatusCode,
	}
	return &rd
}

// CaddyModule returns the Caddy module information
func (RedirDns) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.redir_dns",
		New: func() caddy.Module {
			return New()
		},
	}
}

// Provision implements caddy.Provisioner
func (rd *RedirDns) Provision(ctx caddy.Context) error {
	var err error = nil
	// store reference to the global log
	rd.logger = ctx.Logger()
	// create replacer to expand short placeholders
	rd.replacer = strings.NewReplacer(
		"{scheme}", "{http.request.scheme}",
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{uri}", "{http.request.uri}",
		"{%uri}", "{http.request.uri_escaped}",
		"{path}", "{http.request.uri.path}",
		"{%path}", "{http.request.uri.path_escaped}",
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{query}", "{http.request.uri.query}",
		"{%query}", "{http.request.uri.query_escaped}",
		"{?query}", "{http.request.uri.prefixed_query}",
	)
	// compile error response template
	rd.responseTpl, err = template.New("default").Parse(defaultResponseTemplate)

	return err
}

// Validate implements caddy.Validator
func (rd *RedirDns) Validate() error {
	// Check if default target is supplied and is a valid absolute URL
	if rd.DefaultTarget != "" && !isValidAbsoluteURL(rd.DefaultTarget) {
		return fmt.Errorf("invalid absolute URL default_target '%s'", rd.DefaultTarget)
	}
	// Check if supplied DNS TXT record prefix is valid
	var txtprefixRegex = regexp.MustCompile(`^[_a-zA-Z0-9]([_a-zA-Z0-9-]{0,61}[_a-zA-Z0-9])?$`)
	if !txtprefixRegex.MatchString(rd.DnsPrefix) {
		return fmt.Errorf("invalid dns_prefix '%s'", rd.DnsPrefix)
	}
	// Check if supplied response status code is supported
	if !isSupportedStatusCode(rd.StatusCode) {
		return fmt.Errorf("unsupported status_code %d", rd.StatusCode)
	}
	rd.logger.Info("provisioned module with default values",
		zap.String("default_target", rd.DefaultTarget),
		zap.String("dns_prefix", rd.DnsPrefix),
		zap.Int("status_code", rd.StatusCode),
	)

	return nil
}

func (rd RedirDns) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// extract the host name from the request
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host
	}

	// check if hostname is an IP address
	if ip := net.ParseIP(reqHost); ip != nil {
		rd.logger.Debug("hostname is IP address", zap.String("host", reqHost))
		// hostname is an IP address
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failed", "Unable to redirect an IP address")
	}

	// create DNS TXT query and perform lookup
	txtQuery := rd.DnsPrefix + "." + reqHost
	txtRecord, err := net.LookupTXT(txtQuery)

	// check if the DNS lookup returned a response
	if err != nil || len(txtRecord) == 0 {
		rd.logger.Debug("lookup TXT record failed", zap.Error(err))
		// DNS lookup returned no / invalid response
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failed", "Unable to load TXT DNS record")
	}

	// iterate over each TXT record in the response
	for i, txt := range txtRecord {
		// parse the TXT record to extract redirect location
		targetUrl, statusCode := rd.parseTxtRecord(reqHost, txt, r)
		rd.logger.Debug("parseTxtRecord()", zap.String("host", reqHost),
			zap.String("txtRecord["+strconv.Itoa(i)+"]", txt),
			zap.String("targetUrl", targetUrl), zap.Int("statusCode", statusCode))
		if targetUrl != "" {
			// output HTTP redirect response
			return writeRedirectResponse(w, statusCode, targetUrl)
		}
	}

	// none of the TXT records contained a valid redirect
	if rd.DefaultTarget != "" {
		// redirect to default target if supplied
		return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
	}

	return rd.writeHtmlResponse(w, http.StatusNotFound,
		"Redirect Failed", "Unable to determine redirect target")
}

func writeRedirectResponse(w http.ResponseWriter, statusCode int, location string) error {
	w.Header().Set("Location", location)
	w.WriteHeader(statusCode)

	return nil
}

func (rd RedirDns) writeHtmlResponse(w http.ResponseWriter, statusCode int, title, msg string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	data := map[string]string{
		"Title": title,
		"Msg":   msg,
	}

	return rd.responseTpl.Execute(w, data)
}

func (rd RedirDns) parseTxtRecord(reqHost string, record string, r *http.Request) (string, int) {
	// expand and replace shortcode placeholder values
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	replaced, _ := repl.ReplaceFunc(rd.replacer.Replace(record), func(key string, val any) (any, error) {
		rd.logger.Debug("ReplaceFunc()", zap.String("key", key), zap.Any("val", val))
		// hostname component labels (seperated by dots)
		if strings.HasPrefix(key, "http.request.host.labels.") {
			key = strings.Replace(key, "http.request.host.labels.", "labels.", 1)
		}
		if strings.HasPrefix(key, "labels.") {
			idx, err := strconv.Atoi(key[len("labels."):])
			if err != nil || idx < 0 {
				return "", nil
			}
			components := strings.Split(reqHost, ".")
			if idx >= len(components) {
				return "", nil
			}
			return strings.ToLower(components[len(components)-idx-1]), nil
		}
		// for security reasons, only replace the following placeholders
		switch key {
		case "http.request.scheme",
			"http.request.host",
			"http.request.hostport",
			"http.request.port",
			"http.request.uri",
			"http.request.uri_escaped",
			"http.request.uri.path",
			"http.request.uri.path_escaped",
			"http.request.uri.path.dir",
			"http.request.uri.path.file",
			"http.request.uri.query",
			"http.request.uri.query_escaped",
			"http.request.uri.prefixed_query":
			return val, nil
		default:
			return "", nil
		}
	})
	// set default return values
	targetUrl := ""
	statusCode := rd.StatusCode
	// split the expanded record on whitespace
	parts := strings.Fields(replaced)
	// First part (manditory) should be the target URL
	if len(parts) > 0 {
		if isValidAbsoluteURL(parts[0]) {
			targetUrl = parts[0]
		} else {
			rd.logger.Debug("parseTxtRecord() invalid target hostname", zap.String("host", parts[0]))
		}
	}
	// Second part (optional) could be the status code
	if len(parts) > 1 {
		switch parts[1] {
		case "permanent":
			statusCode = 301
		case "temporary":
			statusCode = 302
		default:
			code, err := strconv.Atoi(parts[1])
			if err == nil && isSupportedStatusCode(code) {
				statusCode = code
			} else {
				rd.logger.Debug("parseTxtRecord() invalid response code", zap.String("code", parts[1]))
			}
		}
	}

	return targetUrl, statusCode
}

func isValidAbsoluteURL(location string) bool {
	parsedUrl, err := url.Parse(location)
	if err != nil {
		return false
	}
	// restrict to HTTP/HTTPS only
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return false
	}
	// must have a non-empty host
	return parsedUrl.Host != ""
}

func isSupportedStatusCode(code int) bool {
	// HTTP response code can be any number in the 3xx range or 401
	if (code >= 300 && code < 400) || code == 401 {
		return true
	}

	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (rd *RedirDns) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "default_target":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.DefaultTarget = d.Val()
			case "dns_prefix":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.DnsPrefix = d.Val()
			case "status_code":
				if !d.NextArg() {
					return d.ArgErr()
				}
				statusCode, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid status code %q: %v", d.Val(), err)
				}
				rd.StatusCode = statusCode
			default:
				return d.Errf("unrecognized configuration option %q", d.Val())
			}
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens into a new RedirDns struct.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rd = New()
	err := rd.UnmarshalCaddyfile(h.Dispenser)
	return rd, err
}

// Interface guard
var (
	_ caddy.Provisioner           = (*RedirDns)(nil)
	_ caddy.Validator             = (*RedirDns)(nil)
	_ caddyhttp.MiddlewareHandler = (*RedirDns)(nil)
	_ caddyfile.Unmarshaler       = (*RedirDns)(nil)
)
