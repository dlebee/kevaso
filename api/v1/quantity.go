package v1

import (
	"fmt"
	"strconv"
	"strings"
)

var suffixes = []struct {
	s string
	n int64
}{
	{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
	{"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
}

// ParseBytes reads a size like 512Mi, 4Gi, 10G or 1048576. Empty is 0.
func ParseBytes(q string) (int64, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0, nil
	}
	mult := int64(1)
	for _, s := range suffixes {
		if strings.HasSuffix(q, s.s) {
			q, mult = strings.TrimSuffix(q, s.s), s.n
			break
		}
	}
	n, err := strconv.ParseInt(q, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("size %q: want a whole number with an optional Ki/Mi/Gi/Ti (or K/M/G/T) suffix", q)
	}
	if mult > 1 && n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q is too large", q)
	}
	return n * mult, nil
}
