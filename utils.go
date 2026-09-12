package forwardauth

import (
	"bytes"
	"encoding/xml"
	"fmt"
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
				if q, ok := parseQValue(strings.TrimSpace(value)); ok {
					quality = q
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
// value and decodes its quoted-pairs, leaving an unquoted token untouched.
//
// Inside a quoted-string a backslash escapes whatever octet follows it (RFC
// 9110 5.6.4); it is not a prefix that only means something before a quote.
// Unescaping just \" left charset="utf\-8" reading as the literal utf\-8,
// which is not a charset this package produces, so a range naming one it CAN
// honour was recorded as unhonourable and dropped --
// "application/json;charset=\"utf\\-8\";q=1, application/xml;q=0.5" answered
// XML.
//
// splitOutsideQuotes already skips the escaped octet when deciding where a
// value ends, so this was the parser knowing one half of a rule and not the
// other.
func unquoteParam(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}

	inner := v[1 : len(v)-1]
	if !strings.ContainsRune(inner, '\\') {
		return inner
	}

	var unescaped strings.Builder
	unescaped.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		// A trailing backslash has nothing to escape, which only a malformed
		// value reaches; it stands for itself rather than being dropped.
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
		}
		unescaped.WriteByte(inner[i])
	}
	return unescaped.String()
}

// parseQValue parses an RFC 9110 12.4.2 qvalue, reporting whether it is one.
//
//	qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
//
// That grammar is much narrower than a float, and strconv.ParseFloat accepted
// the difference: "1e-1", ".5", "0.1234" and "Inf" all parsed. Reading them as
// real priorities let "application/json;q=1e-1, text/html;q=0.5" answer HTML
// off a weight of 0.1 the client never expressed -- a malformed parameter is
// ignored, so the default weight of 1 should have stood and JSON won.
//
// The value is computed here rather than handed back to ParseFloat, so the
// grammar is the only thing that decides what a weight means.
func parseQValue(v string) (float64, bool) {
	whole, frac, hasFrac := strings.Cut(v, ".")
	if whole != "0" && whole != "1" {
		return 0, false
	}
	if hasFrac && len(frac) > 3 {
		return 0, false
	}

	for i := 0; i < len(frac); i++ {
		// "1" admits only zeros after the point: 1.001 is not a weight, and
		// silently clamping it to 1 would accept a header that says something
		// the grammar cannot say.
		if frac[i] < '0' || frac[i] > '9' || (whole == "1" && frac[i] != '0') {
			return 0, false
		}
	}

	if whole == "1" {
		return 1, true
	}

	// Scaled to thousandths and divided once. Accumulating digit by digit --
	// 1*0.1 + 2*0.01 + 3*0.001 -- lands on 0.12300000000000001, which is not
	// the weight the client wrote, and the grammar allows no more precision
	// than this anyway.
	thousandths := 0
	for i := 0; i < 3; i++ {
		thousandths *= 10
		if i < len(frac) {
			thousandths += int(frac[i] - '0')
		}
	}
	return float64(thousandths) / 1000, true
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
		parts      []string
		start      int
		quoteStart int
		inQuote    bool
	)

	for i := 0; i < len(s); i++ {
		switch {
		case inQuote && s[i] == '\\' && i+1 < len(s):
			i++ // the escaped character is never a delimiter
		case s[i] == '"':
			if !inQuote {
				quoteStart = i
			}
			inQuote = !inQuote
		case s[i] == sep && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}

	if inQuote {
		// The quote was never closed, so quoting cannot be trusted from the
		// point it opened -- and only from there. The parts already emitted
		// were split on separators sitting outside a BALANCED quoted string,
		// so they are not in doubt; only the unterminated tail is re-read
		// without quote awareness. Treating the tail as one quoted run let a
		// single stray quote swallow every later media range, so
		// `text/html;q=0;profile="oops, application/json;q=1` parsed as one
		// refused HTML range and the JSON the client actually asked for
		// disappeared.
		//
		// Re-splitting the WHOLE string here instead was the same mistake
		// pointed the other way: one stray quote late in a header corrupted
		// every range before it. `text/html;profile="a,b";q=0,
		// application/json;profile="oops` lost the HTML range's q=0 to the
		// comma inside its own perfectly valid quoted string, and the refused
		// HTML was then what GetPreferredFormat returned.
		//
		// Recovering from the last emitted separator is not far enough
		// either, because a balanced quoted string can sit before the
		// unmatched one INSIDE the same unemitted part:
		// `text/html;profile="a,b";q=0;foo="oops, application/json;q=0` has
		// emitted nothing yet, and re-reading from the start tore that range
		// on the comma in profile. Nothing before the opening quote can
		// contain a separator this loop did not already act on, so that is
		// the earliest point anything is in doubt, and the earliest point
		// worth re-reading.
		recovered := strings.Split(s[quoteStart:], string(sep))
		recovered[0] = s[start:quoteStart] + recovered[0]
		return append(parts, recovered...)
	}

	return append(parts, s[start:])
}

// bestRange returns the range that speaks for mediaType.
//
// Precedence is RFC 9110 12.5.1: an exact type/subtype outranks "type/*",
// which outranks "*/*"; within a shape, a range matching more media-type
// parameters is the more specific one. Equal on both, the earlier range wins.
//
// namesOnly drops the fully generic "*/*" and nothing else, which is the
// narrower question the exported predicates ask: "did the client NAME this
// type?" rather than "would this type be acceptable?". "application/*" DOES
// name the type -- it narrows to application subtypes -- so it counts, while
// "*/*" names nothing and does not.
//
// The distinction has to match the negotiator's or the two disagree: with
// "Accept: application/*" the negotiator settles on JSON, and a predicate that
// rejected type wildcards told the caller the client had not asked for it.
func bestRange(ranges []acceptRange, mediaType string, namesOnly bool) (acceptRange, bool) {
	typ, sub, _ := strings.Cut(mediaType, "/")

	var best acceptRange
	bestShape, bestParams, found := 0, -1, false

	for _, r := range ranges {
		var shape int
		switch {
		case r.typ == typ && r.sub == sub:
			shape = 3
		case r.typ == typ && r.sub == "*":
			shape = 2
		case !namesOnly && r.typ == "*" && r.sub == "*":
			shape = 1
		default:
			continue
		}
		if shape < bestShape || (shape == bestShape && r.params <= bestParams) {
			continue
		}
		best, bestShape, bestParams, found = r, shape, r.params, true
	}

	return best, found
}

// matchAccept returns the weight the header gives mediaType, and the position
// of the range that decided it.
func matchAccept(ranges []acceptRange, mediaType string) (quality float64, order int, matched bool) {
	best, ok := bestRange(ranges, mediaType, false)
	return best.quality, best.order, ok
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

	// The SAME precedence and the SAME two passes the negotiator uses,
	// restricted to ranges that name the type. Both halves matter. Taking the
	// first exact match instead of the best one made the two disagree:
	// "application/json;q=0, application/json;charset=utf-8;q=1" has
	// GetPreferredFormat answer "json" off the more specific range while this
	// read the earlier q=0 and answered false. Skipping the honourable pass
	// did the same in the other direction: with "application/*;q=1,
	// application/json;profile=foo;q=0" the negotiator drops the profile
	// range it cannot honour and sends JSON off "application/*", while this
	// let the refusal it discarded win on shape and answered false.
	named := false
	honourableFirst(parseAccept(header), func(candidates, refusals []acceptRange) bool {
		if refusedByRange(refusals, mediaType) {
			named = false
			return false
		}
		best, ok := bestRange(candidates, mediaType, true)
		named = ok && best.quality > 0
		return named
	})
	return named
}

// honourableRanges keeps the ranges this package can actually honour. A
// media-type parameter narrows what a range matches, and the responses here
// carry none, so a parameterized range does not describe anything that would
// actually be sent.
func honourableRanges(ranges []acceptRange) []acceptRange {
	honourable := make([]acceptRange, 0, len(ranges))
	for _, r := range ranges {
		if !r.unhonourable {
			honourable = append(honourable, r)
		}
	}
	return honourable
}

// honourableFirst calls answered with the honourable ranges and, when that
// pass answers nothing, calls it again with the whole set -- handing it the
// honourable ranges as refusals the second time.
//
// The negotiator and the exported predicates both have to walk the header this
// way, in this order, and agree on when a pass has answered nothing -- a range
// matched at q=0 has not. Every time the two have been written out separately
// they have drifted, so they share the walk instead.
func honourableFirst(ranges []acceptRange, answered func(candidates, refusals []acceptRange) bool) {
	honourable := honourableRanges(ranges)
	if answered(honourable, nil) {
		return
	}
	answered(ranges, honourable)
}

// refusedByRange reports whether any of the given ranges matches mediaType and
// gives it zero weight.
//
// A refusal from a range this package can honour survives the fallback pass.
// The fallback exists because a header naming only representations that cannot
// be produced is better disregarded than answered with 406 (RFC 9110 12.5.1),
// but that is a concession for a question the client left UNANSWERED, and
// "q=0" is an answer. Without it, "application/json;profile=foo;q=1,
// application/json;q=0" fell through to the profile range and sent bare
// application/json -- the one representation the client had explicitly
// refused -- while the same two ranges in the other order correctly sent text,
// because at equal shape and equal satisfied-parameter count bestRange keeps
// whichever it saw first.
func refusedByRange(ranges []acceptRange, mediaType string) bool {
	best, ok := bestRange(ranges, mediaType, false)
	return ok && best.quality <= 0
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
//
// A format refused by one of the refusals ranges is not a candidate at all,
// whatever the ranges say about it. See refusedByRange.
func selectFormat(ranges, refusals []acceptRange) string {
	bestFormat, bestQuality, bestOrder := "", 0.0, 0
	for _, candidate := range negotiatedFormats {
		if refusedByRange(refusals, candidate.mediaType) {
			continue
		}
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

	// Ranges this package can actually honour come first, so
	// "application/xml;q=0.5, application/json;profile=foo;q=1" answers XML:
	// the JSON the client asked for is not the JSON that would be sent, while
	// the XML is exactly what would be sent.
	//
	// When nothing honourable is acceptable the second pass takes the whole
	// header. RFC 9110 12.5.1 lets a server disregard the header rather than
	// refuse, and that is the better answer here: a client asking for
	// "text/html;profile=..." is still far better served the login redirect
	// than a plain-text 401 it did not ask for either.
	format := ""
	honourableFirst(parseAccept(acceptHeader), func(candidates, refusals []acceptRange) bool {
		format = selectFormat(candidates, refusals)
		return format != ""
	})
	if format == "" {
		return "text"
	}

	return format
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
