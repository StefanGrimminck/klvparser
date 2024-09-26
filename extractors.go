package klvparser

import (
	"encoding/binary"
	"fmt"
)

// Extractors for different data types from byte slices.
func extractUint8(value []byte) *uint8 {
	if len(value) >= 1 {
		val := value[0]
		return &val
	}
	return nil
}

func extractUint16(value []byte) *uint16 {
	if len(value) >= 2 {
		val := binary.BigEndian.Uint16(value)
		return &val
	}
	return nil
}

func extractUint32(value []byte) *uint32 {
	if len(value) >= 4 {
		val := binary.BigEndian.Uint32(value)
		return &val
	}
	return nil
}

func extractUint64(value []byte) *uint64 {
	if len(value) >= 8 {
		val := binary.BigEndian.Uint64(value)
		return &val
	}
	return nil
}

func extractInt8(value []byte) *int8 {
	if len(value) >= 1 {
		val := int8(value[0])
		return &val
	}
	return nil
}

func extractScaledUint16(value []byte, scale float64) *float64 {
	if len(value) >= 2 {
		val := float64(binary.BigEndian.Uint16(value)) * scale
		return &val
	}
	return nil
}

func extractScaledUint16WithOffset(value []byte, scale, offset float64) *float64 {
	if len(value) >= 2 {
		val := float64(binary.BigEndian.Uint16(value))*scale + offset
		return &val
	}
	return nil
}

func extractScaledInt16(value []byte, scale float64) *float64 {
	if len(value) < 2 {
		return nil
	}
	val := float64(int16(binary.BigEndian.Uint16(value))) * scale
	return &val
}

func extractScaledInt32(value []byte, scale float64) *float64 {
	if len(value) < 4 {
		return nil
	}
	val := float64(int32(binary.BigEndian.Uint32(value))) * scale
	return &val
}

func extractScaledUint32(value []byte, scale float64) *float64 {
	if len(value) >= 4 {
		val := float64(binary.BigEndian.Uint32(value)) * scale
		return &val
	}
	return nil
}

func extractHex(value []byte) *string {
	if len(value) > 0 {
		hexValue := fmt.Sprintf("%X", value)
		return &hexValue
	}
	return nil
}

func extractInt64(value []byte) *int64 {
	if len(value) >= 8 {
		val := int64(binary.BigEndian.Uint64(value))
		return &val
	}
	return nil
}
