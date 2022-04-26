package profile

import "strings"

// ParseQuery parses a URI-style query into key-value pairs.
func ParseQuery(query string) map[string]string {
	out := make(map[string]string)

	for _, pair := range strings.Split(query, "&") {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			out[kv[0]] = kv[1]
		}
	}

	return out
}
