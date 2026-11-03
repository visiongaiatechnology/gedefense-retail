// BACnet object/property metadata and the event mapping of decoded messages.
package bacnet

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// BACnet object types interpreted by the decoder (per product contract:
// AnalogInput, AnalogValue, BinaryInput, BinaryValue).
const (
	objTypeAnalogInput uint8 = 0
	objTypeAnalogValue uint8 = 2
	objTypeBinaryInput uint8 = 3
	objTypeBinaryValue uint8 = 5
	objTypeDevice      uint8 = 8
)

// Present-Value is the only property the MVP maps onto telemetry.
const propertyPresentValue uint8 = 85

// ObjectMapping is one operator-approved object mapping.
type ObjectMapping struct {
	ObjectType uint8
	Instance   uint32
	SensorID   domain.SensorID
	Metric     string
	Unit       domain.Unit
}

// ParseObjectMappings parses the "objects" option:
//
//	objecttype:instance|sensor_id|metric|unit;next[;...]
func ParseObjectMappings(value string) ([]ObjectMapping, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	entries := strings.Split(value, ";")
	out := make([]ObjectMapping, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		mapping, err := parseObjectMapping(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, mapping)
	}
	return out, nil
}

func parseObjectMapping(entry string) (ObjectMapping, error) {
	parts := strings.Split(entry, "|")
	if len(parts) != 4 {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q needs type:instance|sensor|metric|unit", entry)
	}
	head := strings.SplitN(strings.TrimSpace(parts[0]), ":", 2)
	if len(head) != 2 {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q needs type:instance", entry)
	}
	objType, err := strconv.ParseUint(strings.TrimSpace(head[0]), 10, 8)
	if err != nil || !mappableObjectType(uint8(objType)) {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q: unsupported object type", entry)
	}
	instance, err := strconv.ParseUint(strings.TrimSpace(head[1]), 10, 32)
	if err != nil || instance > maxObjectID {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q: invalid instance", entry)
	}
	sensor := domain.SensorID(strings.TrimSpace(parts[1]))
	if err := sensor.Validate(); err != nil {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q: sensor: %v", entry, err)
	}
	metric := strings.TrimSpace(parts[2])
	if metric == "" || len(metric) > 64 {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q: metric is required", entry)
	}
	unit := domain.Unit(strings.TrimSpace(parts[3]))
	if !unit.Valid() {
		return ObjectMapping{}, fmt.Errorf("bacnet: object mapping %q: invalid unit %q", entry, parts[3])
	}
	return ObjectMapping{
		ObjectType: uint8(objType),
		Instance:   uint32(instance),
		SensorID:   sensor,
		Metric:     metric,
		Unit:       unit,
	}, nil
}

func mappableObjectType(t uint8) bool {
	switch t {
	case objTypeAnalogInput, objTypeAnalogValue, objTypeBinaryInput, objTypeBinaryValue:
		return true
	}
	return false
}

func (m ObjectMapping) matches(t uint8, instance uint32) bool {
	return m.ObjectType == t && m.Instance == instance
}

// objectInfo is the default interpretation of a supported object type.
type objectInfo struct {
	name   string
	binary bool
}

func objectMeta(t uint8) (objectInfo, bool) {
	switch t {
	case objTypeAnalogInput:
		return objectInfo{name: "analog_input"}, true
	case objTypeAnalogValue:
		return objectInfo{name: "analog_value"}, true
	case objTypeBinaryInput:
		return objectInfo{name: "binary_input", binary: true}, true
	case objTypeBinaryValue:
		return objectInfo{name: "binary_value", binary: true}, true
	default:
		return objectInfo{}, false
	}
}

func propertyName(property uint8) string {
	switch property {
	case propertyPresentValue:
		return "present_value"
	case 77:
		return "object_name"
	case 117:
		return "units"
	default:
		return "property_" + strconv.Itoa(int(property))
	}
}

// eventsFor converts one decoded message into normalized events.
func (d *Decoder) eventsFor(remoteIP string, msg message) []domain.Event {
	now := d.opts.Meta.Now()
	switch msg.kind {
	case msgIAm:
		return d.iamEvents(remoteIP, msg, now)
	case msgReadPropertyAck:
		return d.telemetryEvents(msg, now)
	case msgWriteAttempt:
		return d.writeAttemptEvents(remoteIP, msg, now)
	default:
		return nil
	}
}

func (d *Decoder) iamEvents(remoteIP string, msg message, now time.Time) []domain.Event {
	dev := domain.DeviceMeta{IP: remoteIP}
	ev, err := d.opts.Meta.AssetSeenEvent(dev, 0.5, now)
	if err != nil {
		d.counters.IncError(err.Error())
		return nil
	}
	ev.PayloadMeta = map[string]string{
		"bacnet_device_instance": strconv.FormatUint(uint64(msg.deviceInstance), 10),
		"bacnet_vendor_id":       strconv.FormatUint(uint64(msg.vendorID), 10),
	}
	return []domain.Event{ev}
}

func (d *Decoder) telemetryEvents(msg message, now time.Time) []domain.Event {
	info, ok := objectMeta(msg.objectType)
	if !ok || !msg.numeric && !info.binary {
		return nil
	}
	mapping, mapped := d.mappingFor(msg.objectType, msg.objectInstance)
	unit := domain.UnitUnknown
	metric := "present_value"
	confidence := 0.6
	if info.binary {
		metric = "binary_state"
		unit = domain.UnitBoolean
	} else if !msg.numeric {
		return nil
	}
	sensor := domain.SensorID("bacnet_" + strings.ToLower(info.name) + "_" + strconv.FormatUint(uint64(msg.objectInstance), 10))
	if mapped {
		sensor = mapping.SensorID
		metric = mapping.Metric
		unit = mapping.Unit
		confidence = 0.8
	}
	value := msg.value
	if info.binary {
		switch {
		case msg.numeric && value != 0:
			value = 1
		case msg.numeric:
			value = 0
		case msg.boolean:
			value = 1
		default:
			value = 0
		}
	}
	meas := domain.Measurement{
		Value:      value,
		Unit:       unit,
		Quality:    domain.QualityGood,
		Metric:     metric,
		ObservedAt: now,
	}
	ev, err := d.opts.Meta.TelemetryEvent(sensor, "", meas, confidence, now)
	if err != nil {
		d.counters.IncError(err.Error())
		return nil
	}
	ev.PayloadMeta = map[string]string{
		"bacnet_object_type": strconv.Itoa(int(msg.objectType)),
		"bacnet_object_id":   strconv.FormatUint(uint64(msg.objectInstance), 10),
	}
	return []domain.Event{ev}
}

func (d *Decoder) writeAttemptEvents(remoteIP string, msg message, now time.Time) []domain.Event {
	target := "bacnet:unknown"
	if info, ok := objectMeta(msg.objectType); ok {
		target = "bacnet:" + info.name + ":" + strconv.FormatUint(uint64(msg.objectInstance), 10)
	}
	attempt := domain.WriteAttempt{
		Protocol: "bacnet_ip",
		Source:   remoteIP,
		Target:   target,
		Function: msg.serviceName,
		Register: propertyName(msg.property),
		Allowed:  false,
	}
	ev, err := d.opts.Meta.WriteAttemptEvent(attempt, 0.8, now)
	if err != nil {
		d.counters.IncError(err.Error())
		return nil
	}
	return []domain.Event{ev}
}

func (d *Decoder) mappingFor(objType uint8, instance uint32) (ObjectMapping, bool) {
	for _, mapping := range d.opts.Mappings {
		if mapping.matches(objType, instance) {
			return mapping, true
		}
	}
	return ObjectMapping{}, false
}
