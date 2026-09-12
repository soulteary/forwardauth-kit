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
}

// parseAccept parses an Accept header into weighted media ranges.
//
// The weights are the point. RFC 9110 12.4.2 defines q=0 as "not acceptable",
// so "application/json;q=0, text/html;q=1" asks for HTML and explicitly
// REFUSES JSON -- and the weight can sit behind other parameters, as in
// "text/html;level=1;q=0.5", so every parameter has to be scanned.
func parseAccept(header string) []acceptRange {
	var ranges []acceptRange

	for i, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		typ, sub, ok := strings.Cut(strings.ToLower(strings.TrimSpace(fields[0])), "/")
		if !ok || typ == "" || sub == "" {
			continue
		}

		quality := 1.0
		for _, param := range fields[1:] {
			name, value, ok := strings.Cut(param, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			// A malformed weight is not a refusal: RFC 9110 says to ignore
			// the parameter, so the default weight stands.
			if q, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && q >= 0 {
				quality = math.Min(q, 1)
			}
			break
		}

		ranges = append(ranges, acceptRange{typ: typ, sub: sub, quality: quality, order: i})
	}

	return ranges
}

// matchAccept returns the weight the header gives mediaType, and the position
// of the range that decided it.
//
// Precedence is RFC 9110 12.5.1: an exact type/subtype outranks "type/*",
// which outranks "*/*", regardless of the weights -- the most specific range
// is the one that speaks for this type.
func matchAccept(ranges []acceptRange, mediaType string) (quality float64, order int, matched bool) {
	typ, sub, _ := strings.Cut(mediaType, "/")

	best := 0
	for _, r := range ranges {
		var specificity int
		switch {
		case r.typ == typ && r.sub == sub:
			specificity = 3
		case r.typ == typ && r.sub == "*":
			specificity = 2
		case r.typ == "*" && r.sub == "*":
			specificity = 1
		default:
			continue
		}
		if specificity > best {
			best, quality, order, matched = specificity, r.quality, r.order, true
		}
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

// GetPreferredFormat returns the preferred response format based on Accept header.
func GetPreferredFormat(c Context) string {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return "html"
	}

	ranges := parseAccept(acceptHeader)

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

	if bestFormat == "" {
		return "text"
	}

	return bestFormat
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
