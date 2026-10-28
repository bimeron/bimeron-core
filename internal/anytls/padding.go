package anytls

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const defaultPadding = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

type padStep struct {
	min, max int
	check    bool
}

type padScheme struct {
	text  string
	stop  int
	steps map[int][]padStep
}

func parsePadding(text string) (padScheme, error) {
	s := padScheme{text: text, steps: make(map[int][]padStep)}
	if len(text) > 4096 {
		return s, fmt.Errorf("AnyTLS padding scheme is too large")
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return s, fmt.Errorf("invalid AnyTLS padding scheme")
		}
		if key == "stop" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 256 {
				return s, fmt.Errorf("invalid AnyTLS padding stop")
			}
			s.stop = n
			continue
		}
		index, err := strconv.Atoi(key)
		if err != nil || index < 0 || index > 255 || s.steps[index] != nil {
			return s, fmt.Errorf("invalid AnyTLS padding index")
		}
		for _, part := range strings.Split(value, ",") {
			if part == "c" {
				if len(s.steps[index]) == 0 {
					return s, fmt.Errorf("invalid AnyTLS padding check")
				}
				s.steps[index][len(s.steps[index])-1].check = true
				continue
			}
			low, high, ok := strings.Cut(part, "-")
			min, e1 := strconv.Atoi(low)
			max, e2 := strconv.Atoi(high)
			if !ok || e1 != nil || e2 != nil || min < 0 || max < min || max > 16384 || len(s.steps[index]) >= 32 {
				return s, fmt.Errorf("invalid AnyTLS padding range")
			}
			s.steps[index] = append(s.steps[index], padStep{min: min, max: max})
		}
	}
	if s.stop == 0 || len(s.steps[0]) != 1 {
		return s, fmt.Errorf("incomplete AnyTLS padding scheme")
	}
	return s, nil
}

func padSize(step padStep) (int, error) {
	if step.min == step.max {
		return step.min, nil
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return step.min + int(binary.BigEndian.Uint32(b[:])%uint32(step.max-step.min+1)), nil
}
