package klvparser

import (
	"bytes"
	"fmt"
	"log"
)

// MISB0601UL represents the Universal Label for MISB ST 0601 metadata.
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
		// Tag 1: Checksum
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint16(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 2:
		// Tag 2: Precision Time Stamp
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint64(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 3:
		// Tag 3: Mission ID
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 4:
		// Tag 4: Platform Tail Number
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 5:
		// Tag 5: Platform Heading Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 6:
		// Platform Pitch Angle: -20 to 20 degrees
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 40.0/65535.0)
		})

	case 7:
		// Platform Roll Angle: -20 to 20 degrees
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 40.0/65535.0)
		})
	case 8:
		// Tag 8: Platform True Airspeed
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 9:
		// Tag 9: Platform Indicated Airspeed
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 10:
		// Tag 10: Platform Designation
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 11:
		// Tag 11: Image Source Sensor
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 12:
		// Tag 12: Image Coordinate System
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 13:
		// Tag 13: Sensor Latitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 14:
		// Tag 14: Sensor Longitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 360.0/(1<<31-1))
		})
	case 15:
		// Tag 15: Sensor True Altitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 16:
		// Tag 16: Sensor Horizontal Field of View
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 17:
		// Tag 17: Sensor Vertical Field of View
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 18:
		// Tag 18: Sensor Relative Azimuth Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint32(val, 360.0/4294967295.0)
		})
	case 19:
		// Tag 19: Sensor Relative Elevation Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 40.0/65535.0)
		})
	case 20:
		// Tag 20: Sensor Relative Roll Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint32(val, 360.0/4294967295.0)
		})
	case 21:
		// Tag 21: Slant Range
		if val := extractUint32(value); val != nil {
			convertedVal := float64(*val)
			meta := tagMeta[int(tag)]
			if meta != nil {
				meta.Value = convertedVal
			}
		}
	case 22:
		// Tag 22: Target Width
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 10000.0/65535.0)
		})
	case 23:
		// Tag 23: Frame Center Latitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 24:
		// Tag 24: Frame Center Longitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 25:
		// Tag 25: Frame Center Elevation
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 26:
		// Tag 26: Offset Corner Latitude Point 1
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 27:
		// Tag 27: Offset Corner Longitude Point 1
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 28:
		// Tag 28: Offset Corner Latitude Point 2
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 29:
		// Tag 29: Offset Corner Longitude Point 2
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 30:
		// Tag 30: Offset Corner Latitude Point 3
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 31:
		// Tag 31: Offset Corner Longitude Point 3
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 32:
		// Tag 32: Offset Corner Latitude Point 4
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 33:
		// Tag 33: Offset Corner Longitude Point 4
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 0.075/32767.0)
		})
	case 34:
		// Tag 34: Target Error Estimate CE90
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 35:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 4095.0/65535.0)
		})
	case 36:
		// Tag 36: Generic Flag Data 01
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 37:
		// Tag 37: Security Local Metadata Set
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 5000.0/65535.0)
		})
	case 38:
		// Tag 38: Differential Pressure
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 39:
		// Tag 39: Platform Angle of Attack
		processValue(int(tag), value, func(val []byte) *float64 {
			if intVal := extractInt8(val); intVal != nil {
				convertedVal := float64(*intVal)
				return &convertedVal
			}
			return nil
		})
	case 40:
		// Tag 40: Platform Sideslip Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 40.0/65535.0)
		})
	case 41:
		// Tag 41: Airfield Barometric Pressure
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 42:
		// Tag 42: Airfield Elevation
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 43:
		// Tag 43: Relative Humidity
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 44:
		// Tag 44: Platform Ground Speed
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 45:
		// Tag 45: Target Error Estimate - CE90
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 4095.0/65535.0) // Resolution of 0.0624 meters
		})
	case 46:
		// Tag 46: Target Error Estimate - LE90
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 4095.0/65535.0) // Resolution of 0.0625 meters
		})
	case 47:
		// Tag 47: Platform Call Sign
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 48:
		// Tag 48: Weapon Load
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 49:
		// Tag 49: Weapon Fired
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 50:
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 40.0/65534.0)
		})
	case 51:
		// Platform Vertical Speed
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 360.0/65534.0)
		})
	case 52:
		// Platform Sideslip Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 1.0)
		})
	case 53:
		// Airfield Barometric Pressure
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 5000.0/65535.0)
		})
	case 54:
		// Airfield Elevation
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 1.0)
		})
	case 55:
		// Relative Humidity
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint8(val, 1.0)
		})
	case 56:
		// Platform Ground Speed
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint8(val, 1.0)
		})
	case 57:
		// Ground Range
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint32 := extractUint32(val)
			if valUint32 != nil {
				floatVal := float64(*valUint32)
				return &floatVal
			}
			return nil
		})

	case 58:
		// Platform Fuel Remaining
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 1.0)
		})
	case 59:
		// Platform Call Sign
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 60:
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint16 := extractUint16(val)
			if valUint16 != nil {
				floatVal := float64(*valUint16)
				return &floatVal
			}
			return nil
		})

	case 61:
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint8 := extractUint8(val)
			if valUint8 != nil {
				floatVal := float64(*valUint8)
				return &floatVal
			}
			return nil
		})
	case 62:
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint16 := extractUint16(val)
			if valUint16 != nil {
				floatVal := float64(*valUint16)
				return &floatVal
			}
			return nil
		})
	case 63:
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint8 := extractUint8(val)
			if valUint8 != nil {
				floatVal := float64(*valUint8)
				return &floatVal
			}
			return nil
		})

	case 64:
		// Platform Magnetic Heading
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 65:
		// UAS Datalink LS Version Number
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 66:
		// Deprecated
		fmt.Println("Deprecated tag")
	case 67:
		// Alternate Platform Latitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 68:
		// Alternate Platform Longitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 69:
		// Alternate Platform Altitude
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16WithOffset(val, 19900.0/65535.0, -900.0)
		})
	case 70:
		// Alternate Platform Name
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 71:
		// Alternate Platform Heading
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 360.0/65535.0)
		})
	case 72:
		// Event Start Time
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint64(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 73:
		// RVT Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 74:
		// VMTI Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 75:
		// Sensor Ellipsoid Height
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 1.0)
		})
	case 76:
		// Alternate Platform Ellipsoid Height
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 1.0)
		})
	case 77:
		// Operational Mode (Tag 77, uint8)
		processValue(int(tag), value, func(val []byte) *float64 {
			valUint8 := extractUint8(val)
			if valUint8 != nil {
				floatVal := float64(*valUint8)
				return &floatVal
			}
			return nil
		})
	case 78:
		// Frame Center Height Above Ellipsoid
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledUint16(val, 1.0)
		})
	case 79:
		// Sensor North Velocity
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 1.0)
		})
	case 80:
		// Sensor East Velocity
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt16(val, 655.34/65535.0)
		})
	case 81:
		// Image Horizon Pixel Pack
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 82:
		// Corner Latitude Point 1 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 83:
		// Corner Longitude Point 1 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 84:
		// Corner Latitude Point 2 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 85:
		// Corner Longitude Point 2 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 86:
		// Corner Latitude Point 3 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 87:
		// Corner Longitude Point 3 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 88:
		// Corner Latitude Point 4 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 89:
		// Corner Longitude Point 4 (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 180.0/(1<<31-1))
		})
	case 90:
		// Platform Pitch Angle (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 91:
		// Platform Roll Angle (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 92:
		// Platform Angle of Attack (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 93:
		// Platform Sideslip Angle (Full)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractScaledInt32(val, 90.0/(1<<31-1))
		})
	case 94:
		// MIIS Core Identifier
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 95:
		// SAR Motion Imagery Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 96:
		// Tag 96: Target Width Extended
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 97:
		// Range Image Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 98:
		// Geo-Registration Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 99:
		// Composite Imaging Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 100:
		// Segment Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 101:
		// Amend Local Set
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 102:
		// SDCC-FLP
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 103:
		// Tag 103: Density Altitude Extended
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 104:
		// Tag 104: Sensor Ellipsoid Height Extended
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 105:
		// Tag 105: Alternate Platform Ellipsoid Height Extended
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 106:
		// Stream Designator
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 107:
		// Operational Base
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 108:
		// Broadcast Source
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 109:
		// Tag 109: Range to Recovery Location
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 110:
		// Time Airborne
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint32(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 111:
		// Propulsion Unit Speed
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint32(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 112:
		// Tag 112: Platform Course Angle
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 113:
		// Tag 113: Altitude Above Ground Level (AGL)
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 114:
		// Tag 114: Radar Altimeter
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 115:
		// Control Command
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 116:
		// Control Command Verification List
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 117:
		// Tag 117: Sensor Azimuth Rate
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 118:
		// Tag 118: Sensor Elevation Rate
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 119:
		// Tag 119: Sensor Roll Rate
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 120:
		// Tag 120: On-board MI Storage Percent Full
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})

	case 121:
		// Active Wavelength List
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 122:
		// Country Codes
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 123:
		// Number of NAVSATs in View
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 124:
		// Positioning Method Source
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 125:
		// Platform Status
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 126:
		// Sensor Control Mode
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint8(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 127:
		// Sensor Frame Rate Pack
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 128:
		// Wavelengths List
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 129:
		// Target ID
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 130:
		// Airbase Locations
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 131:
		// Take-off Time
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint64(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 132:
		// Tag 132: Transmission Frequency
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 133:
		// On-board MI Storage Capacity
		processValue(int(tag), value, func(val []byte) *float64 {
			if uintVal := extractUint32(val); uintVal != nil {
				convertedVal := float64(*uintVal)
				return &convertedVal
			}
			return nil
		})
	case 134:
		// Tag 134: Zoom Percentage
		processValue(int(tag), value, func(val []byte) *float64 {
			return extractIMAPB(val)
		})
	case 135:
		// Communications Method
		val := string(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 136:
		// Leap Seconds
		processValue(int(tag), value, func(val []byte) *float64 {
			if intVal := extractInt32(val); intVal != nil {
				convertedVal := float64(*intVal)
				return &convertedVal
			}
			return nil
		})
	case 137:
		// Correction Offset
		processValue(int(tag), value, func(val []byte) *float64 {
			if intVal := extractInt64(val); intVal != nil {
				convertedVal := float64(*intVal)
				return &convertedVal
			}
			return nil
		})
	case 138:
		// Payload List
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 139:
		// Active Payloads
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 140:
		// Weapons Stores
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 141:
		// Waypoint List
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 142:
		// View Domain
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	case 143:
		// Metadata Substream ID Pack
		val := extractHex(value)
		meta := tagMeta[int(tag)]
		if meta != nil {
			meta.Value = val
		}
	default:
		fmt.Printf("Warning: Unknown tag: %d\n", tag)
	}
}
