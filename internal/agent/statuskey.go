package agent

import "encoding/json"

// statusKey is a status's content, to tell whether a write would change anything (%+v would print
// nested pointers' addresses, not what they point to).
func statusKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
