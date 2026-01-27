package forwardauth

import (
	"fmt"
	"strings"
)

// IsHTMLRequest checks if the request accepts HTML responses.
// It examines the Accept header to determine if the client expects HTML content.
//
// Returns true if:
//   - Accept header is empty (defaults to HTML)
//   - Accept header contains "text/html"
//   - Accept header starts with "*/*" (accepts all types)
func IsHTMLRequest(c Context) bool {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return true // Default to HTML request
	}

	acceptParts := strings.Split(acceptHeader, ",")
	for i, acceptPart := range acceptParts {
		format := strings.Trim(strings.SplitN(acceptPart, ";", 2)[0], " ")
		if format == "text/html" || (i == 0 && format == "*/*") {
			return true
		}
	}
	return false
}

// IsJSONRequest checks if the request accepts JSON responses.
func IsJSONRequest(c Context) bool {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return false
	}

	return strings.Contains(acceptHeader, "application/json")
}

// IsXMLRequest checks if the request accepts XML responses.
func IsXMLRequest(c Context) bool {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return false
	}

	return strings.Contains(acceptHeader, "application/xml")
}

// GetPreferredFormat returns the preferred response format based on Accept header.
func GetPreferredFormat(c Context) string {
	acceptHeader := c.Get("Accept")
	if acceptHeader == "" {
		return "html"
	}

	acceptParts := strings.Split(acceptHeader, ",")
	for _, acceptPart := range acceptParts {
		format := strings.Trim(strings.SplitN(acceptPart, ";", 2)[0], " ")
		switch {
		case strings.HasPrefix(format, "application/json"):
			return "json"
		case strings.HasPrefix(format, "application/xml"):
			return "xml"
		case format == "text/html" || format == "*/*":
			return "html"
		}
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
		return c.Status(statusCode).SendString(fmt.Sprintf(`<errors><error code="%d">%s</error></errors>`, statusCode, message))
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
