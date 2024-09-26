package klvparser

import (
	"bytes"
	"fmt"
	"log"
)

// MISB0601UL represents the Universal Label for MISB ST 0601 metadata.
// This constant is used to identify the start of a KLV packet containing MISB 0601 data.
var MISB0601UL = []byte{0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00}

// KLVParser is responsible for parsing MISB 0601 KLV data.
type KLVParser struct {
	buffer   []byte
	callback func(map[int]*KLVTag)
}

// NewKLVParser initializes a new KLVParser with a callback function.
func NewKLVParser(callback func(map[int]*KLVTag)) *KLVParser {
	return &KLVParser{
		buffer:   make([]byte, 0, 1024),
		callback: callback,
	}
}

// ProcessChunk processes a chunk of data and extracts KLV packets.
func (p *KLVParser) ProcessChunk(chunk []byte) error {
	p.buffer = append(p.buffer, chunk...)
	for {
		startIndex := bytes.Index(p.buffer, MISB0601UL)
		if startIndex == -1 {
			return nil
		}

		packet, remainingData, err := p.extractKLVPacket(p.buffer[startIndex:])
		if err != nil {
			return fmt.Errorf("failed to extract KLV packet: %w", err)
		}

		if packet != nil {
			if err := p.parseKLVPacket(packet); err != nil {
				log.Printf("failed to parse KLV packet: %v", err)
			}

			p.buffer = remainingData
		} else {
			break
		}
	}
	return nil
}

// parseKLVPacket handles parsing of individual KLV packets.
func (p *KLVParser) parseKLVPacket(klvPacket []byte) error {
	if len(klvPacket) < 17 {
		return fmt.Errorf("incomplete KLV packet with length %d, skipping", len(klvPacket))
	}

	valueStart, length := p.getValueStartAndLength(klvPacket)
	expectedTotalLength := 16 + 1 + length

	if len(klvPacket) < expectedTotalLength {
		return fmt.Errorf("KLV packet too short. Length: %d, Expected: %d", len(klvPacket), expectedTotalLength)
	}

	klvValue := klvPacket[valueStart : valueStart+length]
	p.parseMetadata(klvValue)

	return nil
}

// parseMetadata processes the tag values in the KLV packet.
func (p *KLVParser) parseMetadata(valueBytes []byte) {
	parsedTags := make(map[int]*KLVTag)
	index := 0
	for index < len(valueBytes) {
		tag := valueBytes[index]
		index++
		_, tagValue, newIndex := p.extractTagValue(valueBytes, index)
		index = newIndex
		p.processTag(tag, tagValue)
		if tagMeta[int(tag)] != nil {
			parsedTags[int(tag)] = tagMeta[int(tag)]
		}
	}
	p.callback(parsedTags)
}

// processTag processes an individual tag based on its value and type.
func (p *KLVParser) processTag(tag uint8, value []byte) {
	switch tag {
	case 1:
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint16(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 2, 72:
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint64(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 3, 4, 10, 11, 12, 59, 70:
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 5, 16, 17, 35, 64, 71:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 6, 7, 19, 50, 51, 52:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 20.0/32767.0)
		})
	case 8, 9, 34, 36, 43, 44, 55, 56, 62, 63, 65, 77, 122, 124, 125:
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 13, 14, 23, 24, 40, 41, 67, 68, 82, 83, 84, 85, 86, 87, 88, 89:
		processValue(int(tag), value, func(val []byte) *float64 {
			if tag == 13 || tag == 23 || tag == 40 || tag == 82 || tag == 84 || tag == 86 || tag == 88 {
				return extractScaledInt32(val, 90.0/(1<<31-1))
			}
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 15, 25, 38, 42, 54, 69, 75, 76, 78:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 18, 20:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint32(val, 360.0/4294967295.0)
		})
	case 79, 80:
		processValue(int(tag), value, func(val []byte) *float64 {
			if len(val) >= 2 {
				return extractScaledInt16(val, 0.01)
			}
			return nil
		})
	case 21, 57, 91:
		if val := extractUint32(value); val != nil {
			convertedVal := float64(*val)
			meta := tagMeta[int(tag)]
			if meta != nil {
				meta.Value = convertedVal
			}
		}
	case 22:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 10000.0/65535.0)
		})
	case 39: // Outside Air Temperature
		processValue(int(tag), value, func(val []byte) *float64 {
			if intVal := extractInt8(val); intVal != nil {
				convertedVal := float64(*intVal)
				return &convertedVal
			}
			return nil
		})
	case 45, 46:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 0.0625)
		})
	case 26, 27, 28, 29, 30, 31, 32, 33:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 47:
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 48, 60, 61, 66, 94, 81:
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 37, 49, 53:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 5000.0/65535.0)
		})
	case 58:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 10000.0/65535.0)
		})
	case 73, 74:
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 90, 92, 93:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.01) // Assuming 0.01 scaling factor
		})
	case 95:
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 137:
		processValue(int(tag), value, func(val []byte) *float64 {
			if intVal := extractInt64(val); intVal != nil {
				convertedVal := float64(*intVal)
				return &convertedVal
			}
			return nil
		})
	case 143:
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	default:
		fmt.Printf("Warning: Unknown tag: %d\n", tag)
	}
}
