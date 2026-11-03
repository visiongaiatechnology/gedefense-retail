// Topic-to-sensor mapping and telemetry payload parsing.
package mqtt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// TopicMapping maps one topic filter to a normalized sensor/metric/unit.
type TopicMapping struct {
	Filter   string
	SensorID domain.SensorID
	AssetID  domain.AssetID
	Metric   string
	Unit     domain.Unit
}

// ParseTopicMappings parses the "sensors" option:
//
//	topic_filter|sensor_id|metric|unit;next[;...]
//
// The topic filter may contain '+' and '#' wildcards (the adapter only
// subscribes to it when wildcards were explicitly allowed).
func ParseTopicMappings(value string) ([]TopicMapping, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	entries := strings.Split(value, ";")
	out := make([]TopicMapping, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		mapping, err := parseTopicMapping(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, mapping)
	}
	return out, nil
}

func parseTopicMapping(entry string) (TopicMapping, error) {
	parts := strings.Split(entry, "|")
	if len(parts) != 4 {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q needs topic|sensor_id|metric|unit", entry)
	}
	filter := strings.TrimSpace(parts[0])
	if err := validateUTF8String(filter, 256); err != nil {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q: %w", entry, err)
	}
	if err := validateTopicFilter(filter, true); err != nil {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q: %w", entry, err)
	}
	sensor := domain.SensorID(strings.TrimSpace(parts[1]))
	if err := sensor.Validate(); err != nil {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q: sensor: %v", entry, err)
	}
	metric := strings.TrimSpace(parts[2])
	if metric == "" || len(metric) > 64 {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q: metric is required (max 64)", entry)
	}
	unit := domain.Unit(strings.TrimSpace(parts[3]))
	if !unit.Valid() {
		return TopicMapping{}, fmt.Errorf("mqtt: sensor mapping %q: invalid unit %q", entry, parts[3])
	}
	return TopicMapping{Filter: filter, SensorID: sensor, Metric: metric, Unit: unit}, nil
}

// validateTopicFilter enforces the MQTT 3.1.1 topic filter rules relevant to
// this product. Wildcards are rejected unless explicitly enabled (data-flood
// risk); '#' must be the last level and precede no other characters.
func validateTopicFilter(filter string, allowWildcard bool) error {
	if filter == "" || len(filter) > 256 {
		return fmt.Errorf("%w: topic filter length", ErrBadPacket)
	}
	if err := validateUTF8String(filter, 256); err != nil {
		return err
	}
	if strings.Contains(filter, "#") || strings.Contains(filter, "+") {
		if !allowWildcard {
			return fmt.Errorf("mqtt: wildcards are disabled (set option allow_wildcard=1 explicitly)")
		}
	}
	levels := strings.Split(filter, "/")
	for i, level := range levels {
		if strings.Contains(level, "#") {
			if level != "#" || i != len(levels)-1 {
				return fmt.Errorf("%w: '#' must be the last level", ErrBadPacket)
			}
		}
		if strings.Contains(level, "+") && level != "+" {
			return fmt.Errorf("%w: '+' must be a whole level", ErrBadPacket)
		}
	}
	return nil
}

// Matches reports whether the filter matches the concrete topic.
func (m TopicMapping) Matches(topic string) bool { return topicMatches(m.Filter, topic) }

func topicMatches(filter, topic string) bool {
	fl := strings.Split(filter, "/")
	tl := strings.Split(topic, "/")
	for i := 0; i < len(fl); i++ {
		if fl[i] == "#" {
			return true
		}
		if i >= len(tl) {
			return false
		}
		if fl[i] == "+" {
			continue
		}
		if fl[i] != tl[i] {
			return false
		}
	}
	return len(fl) == len(tl)
}

// findMapping returns the first mapping that matches the topic.
func findMapping(mappings []TopicMapping, topic string) (TopicMapping, bool) {
	for _, mapping := range mappings {
		if mapping.Matches(topic) {
			return mapping, true
		}
	}
	return TopicMapping{}, false
}

// parsePayload extracts a numeric telemetry value. Supported: plain numbers and
// a small JSON object {"value": number, "unit": "celsius"}. Anything else is
// rejected so no pseudo measurement is produced.
func parsePayload(payload []byte) (value float64, unitHint domain.Unit, ok bool) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" || len(trimmed) > maxPublishPayload {
		return 0, "", false
	}
	if trimmed[0] == '{' {
		var decoded struct {
			Value *float64 `json:"value"`
			Unit  string   `json:"unit"`
		}
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil || decoded.Value == nil {
			return 0, "", false
		}
		if math.IsNaN(*decoded.Value) || math.IsInf(*decoded.Value, 0) {
			return 0, "", false
		}
		return *decoded.Value, domain.Unit(strings.TrimSpace(decoded.Unit)), true
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, "", false
	}
	return parsed, "", true
}
