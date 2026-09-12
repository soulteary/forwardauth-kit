package forwardauth

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// IsHTMLRequest reports whether an HTML response is what this client wants.
//
// It is defined as agreement with GetPreferredFormat, and deliberately so:
// the two decide the same question for the same request, and disagreeing
// stranded the caller. "Accept: application/x-custom, */*" is a plain example
// -- the wildcard means HTML is acceptable, so GetPreferredFormat answers
// "html", but a positional check that only honoured a leading "*/*" answered
// false. HandleNotAuthenticated then skipped the login redirect and
// SendErrorResponse, seeing "html" with no HTML branch, fell through to a
// plain-text 401.
//
// Returns true when the Accept header is absent, names text/html, or reaches a
// "*/*" without an earlier application/json or application/xml having already
// settled the question.
func IsHTMLRequest(c Context) bool {
	return GetPreferredFormat(c) == "html"
}

// IsJSONRequest checks if the request accepts JSON responses.
func IsJSONRequest(c Context) bool {
	return namesMediaType(c.Get("Accept"), "application/json")
}

// IsXMLRequest checks if the request accepts XML responses.
func IsXMLRequest(c Context) bool {
	return namesMediaType(c.Get("Accept"), "application/xml")
}

// acceptRange is one parsed media range of an Accept header.
type acceptRange struct {
	typ     string  // lowercased primary type, "*" for a wildcard
	sub     string  // lowercased subtype, "*" for a wildcard
	quality float64 // the q parameter; 1 when absent
	order   int     // position in the header, for tie-breaking
	// params counts the media-type parameters this package DOES satisfy. RFC
	// 9110 12.5.1 ranks a range with more matching parameters as more
	// specific, so "application/json;charset=utf-8;q=0" outranks a bare
	// "application/json;q=1" and its refusal is the one that controls.
	params int
	// unhonourable is set when the range carries a media-type parameter this
	// package cannot produce. Its responses are bare "application/json",
	// "application/xml" and "text/html", so a range naming anything more
	// specific -- a profile, a version, a non-UTF-8 charset -- is not actually
	// matched by what would be sent.
	unhonourable bool
}

// parseAccept parses an Accept header into weighted media ranges.
//
// The weights are the point. RFC 9110 12.4.2 defines q=0 as "not acceptable",
// so "application/json;q=0, text/html;q=1" asks for HTML and explicitly
// REFUSES JSON -- and the weight can sit behind other parameters, as in
// "text/html;level=1;q=0.5", so every parameter has to be scanned.
func parseAccept(header string) []acceptRange {
	var ranges []acceptRange

	for i, part := range splitOutsideQuotes(header, ',') {
		fields := splitOutsideQuotes(part, ';')
		typ, sub, ok := strings.Cut(strings.ToLower(strings.TrimSpace(fields[0])), "/")
		if !ok || typ == "" || sub == "" {
			continue
		}

		quality, seenQ, unhonourable := 1.0, false, false
		params := 0
		for _, param := range fields[1:] {
			name, value, hasValue := strings.Cut(param, "=")
			name = strings.TrimSpace(name)

			if !seenQ && strings.EqualFold(name, "q") {
				seenQ = true
				// A malformed weight is not a refusal: RFC 9110 says to
				// ignore the parameter, so the default weight stands.
				if q, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && q >= 0 {
					quality = math.Min(q, 1)
				}
				continue
			}
			if seenQ {
				// Everything after q is an accept-ext (RFC 9110 12.5.1), not
				// a media-type parameter, so it says nothing about which
				// representation would match.
				continue
			}

			// A media-type parameter. It narrows what the range matches, and
			// this package emits no parameters -- except that its output IS
			// UTF-8, so charset=utf-8 is one it genuinely satisfies.
			if hasValue && strings.EqualFold(name, "charset") &&
				strings.EqualFold(unquoteParam(strings.TrimSpace(value)), "utf-8") {
				params++
				continue
			}
			unhonourable = true
		}

		ranges = append(ranges, acceptRange{
			typ: typ, sub: sub, quality: quality, order: i,
			params: params, unhonourable: unhonourable,
		})
	}

	return ranges
}

// unquoteParam removes the surrounding quotes of a quoted-string parameter
// value, leaving an unquoted token untouched.
func unquoteParam(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`)
	}
	return v
}

// splitOutsideQuotes splits on sep, ignoring separators inside a quoted
// string.
//
// A media-type parameter value may be a quoted-string (RFC 9110 5.6.6), and it
// may contain the very characters that delimit the list:
//
//	Accept: text/html;profile="a,b";q=0, application/json;q=1
//
// Splitting that on a raw comma tears the HTML range in two, so its q=0 is
// lost and HTML is recorded at the default weight of 1 -- the tie-break then
// picks HTML and redirects a client that explicitly refused it. A backslash
// escapes the next character inside a quoted string, so it is skipped too.
func splitOutsideQuotes(s string, sep byte) []string {
	var (
		parts   []string
		start   int
		inQuote bool
	)

	for i := 0; i < len(s); i++ {
		switch {
		case inQuote && s[i] == '\\' && i+1 < len(s):
			i++ // the escaped character is never a delimiter
		case s[i] == '"':
			inQuote = !inQuote
		case s[i] == sep && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}

	if inQuote {
		// The quote was never closed, so the header is malformed and the
		// quoting cannot be trusted to mean anything. Ignoring it entirely for
		// this string is the recoverable reading: treating the rest as one
		// quoted run let a single stray quote swallow every later media range,
		// so `text/html;q=0;profile="oops, application/json;q=1` parsed as one
		// refused HTML range and the JSON the client actually asked for
		// disappeared.
		return strings.Split(s, string(sep))
	}

	return append(parts, s[start:])
}

// matchAccept returns the weight the header gives mediaType, and the position
// of the range that decided it.
//
// Precedence is RFC 9110 12.5.1: an exact type/subtype outranks "type/*",
// which outranks "*/*", regardless of the weights -- the most specific range
// is the one that speaks for this type.
func matchAccept(ranges []acceptRange, mediaType string) (quality float64, order int, matched bool) {
	typ, sub, _ := strings.Cut(mediaType, "/")

	bestShape, bestParams := 0, -1
	for _, r := range ranges {
		var shape int
		switch {
		case r.typ == typ && r.sub == sub:
			shape = 3
		case r.typ == typ && r.sub == "*":
			shape = 2
		case r.typ == "*" && r.sub == "*":
			shape = 1
		default:
			continue
		}
		// Shape first, then the number of matching parameters: RFC 9110
		// 12.5.1 makes a range with more of them the more specific match, so
		// "application/json;charset=utf-8;q=0" speaks for JSON over a bare
		// "application/json;q=1" that appeared earlier. Equal on both, the
		// earlier range wins.
		if shape < bestShape || (shape == bestShape && r.params <= bestParams) {
			continue
		}
		bestShape, bestParams = shape, r.params
		quality, order, matched = r.quality, r.order, true
	}

	return quality, order, matched
}

// namesMediaType reports whether the header names mediaType exactly, with a
// non-zero weight.
//
// Deliberately narrower than matchAccept: this keeps answering the question
// IsJSONRequest and IsXMLRequest have always answered -- "did the client ask
// for this type?" -- so "*/*" still does not count as asking for JSON. What
// changes is that an explicit q=0, which is a refusal, no longer reads as a
// request for the type it refuses.
func namesMediaType(header, mediaType string) bool {
	if header == "" {
		return false
	}

	typ, sub, _ := strings.Cut(mediaType, "/")
	for _, r := range parseAccept(header) {
		if r.typ == typ && r.sub == sub {
			return r.quality > 0
		}
	}

	return false
}

// negotiatedFormats are the formats SendErrorResponse can produce, in the
// order that breaks a tie between equally weighted ranges.
//
// HTML leads so that a single "*/*" -- which matches all three equally, from
// the same position -- still resolves to HTML, as it always has. A format
// named EARLIER in the header still wins on a tie, so "application/json,
// text/html" is JSON.
var negotiatedFormats = []struct {
	format    string
	mediaType string
}{
	{"html", "text/html"},
	{"json", "application/json"},
	{"xml", "application/xml"},
}

// selectFormat picks the best-weighted format among the given ranges, or ""
// when none of them is acceptable.
func selectFormat(ranges []acceptRange) string {
	bestFormat, bestQuality, bestOrder := "", 0.0, 0
	for _, candidate := range negotiatedFormats {
		quality, order, matched := matchAccept(ranges, candidate.mediaType)
		if !matched || quality <= 0 {
			continue
		}
		if bestFormat != "" && !(quality > bestQuality || (quality == bestQuality && order < bestOrder)) {
			continue
		}
		bestFormat, bestQuality, bestOrder = candidate.format, quality, order
	}
	return bestFormat
}

// GetPreferredFormat returns the preferred response format based on Accept header.
func GetPreferredFormat(c Context) string {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return "html"
	}

	ranges := parseAccept(acceptHeader)

	// Ranges this package can actually honour come first. A media-type
	// parameter narrows what a range matches, and the responses here carry
	// none, so "application/xml;q=0.5, application/json;profile=foo;q=1" must
	// answer XML: the JSON the client asked for is not the JSON that would be
	// sent, while the XML is exactly what would be sent.
	honourable := make([]acceptRange, 0, len(ranges))
	for _, r := range ranges {
		if !r.unhonourable {
			honourable = append(honourable, r)
		}
	}
	if format := selectFormat(honourable); format != "" {
		return format
	}

	// Nothing fully acceptable. RFC 9110 12.5.1 lets a server disregard the
	// header rather than refuse, and that is the better answer here: a client
	// asking for "text/html;profile=..." is still far better served the login
	// redirect than a plain-text 401 it did not ask for either.
	if format := selectFormat(ranges); format != "" {
		return format
	}

	return "text"
}

// SendErrorResponse sends an error response in the format preferred by the client.
// It automatically detects the best response format based on the Accept header:
//   - application/json -> JSON format with error object
//   - application/xml -> XML format with error element
//   - default -> plain text
func SendErrorResponse(c Context, statusCode int, message string) error {
	format := GetPreferredFormat(c)

	switch format {
	case "json":
		c.Set("Content-Type", "application/json")
		return c.Status(statusCode).JSON(map[string]interface{}{
			"error": message,
			"code":  statusCode,
		})
	case "xml":
		c.Set("Content-Type", "application/xml")
		// The message is interpolated into markup, so it has to be escaped.
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(message)); err != nil {
			escaped.Reset()
		}
		return c.Status(statusCode).SendString(fmt.Sprintf(`<errors><error code="%d">%s</error></errors>`, statusCode, escaped.String()))
	default:
		c.Set("Content-Type", "text/plain")
		return c.Status(statusCode).SendString(message)
	}
}

// ScopesContain checks if the scopes slice contains the target scope.
func ScopesContain(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// MergeScopesUnique merges two scope slices and removes duplicates.
func MergeScopesUnique(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// ParseScopesFromHeader parses comma-separated scopes from a header value.
func ParseScopesFromHeader(header string) []string {
	if header == "" {
		return nil
	}

	parts := strings.Split(header, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}
