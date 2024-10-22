package klvparser

import (
	"encoding/binary"
	"fmt"
)

// Extractors for 8-bit data types
func extractUint8(value []byte) *uint8 {
	if len(value) >= 1 {
		val := value[0]
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

func extractScaledUint8(value []byte, scale float64) *float64 {
	if len(value) >= 1 {
		val := float64(value[0]) * scale
		return &val
	}
	return nil
}

// Extractors for 16-bit data types
func extractUint16(value []byte) *uint16 {
	if len(value) >= 2 {
		val := binary.BigEndian.Uint16(value)
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

// Extractors for 32-bit data types
func extractUint32(value []byte) *uint32 {
	if len(value) >= 4 {
		val := binary.BigEndian.Uint32(value)
		return &val
	}
	return nil
}

func extractInt32(value []byte) *int32 {
	if len(value) >= 4 {
		val := int32(binary.BigEndian.Uint32(value)) // Convert bytes to uint32, then cast to int32
		return &val
	}
	return nil
}

func extractScaledUint32(value []byte, scale float64) *float64 {
	if len(value) >= 4 {
		val := float64(binary.BigEndian.Uint32(value)) * scale
		return &val
	}
	return nil
}

func extractScaledInt32(value []byte, scale float64) *float64 {
	if len(value) < 4 {
		return nil
	}
	val := float64(int32(binary.BigEndian.Uint32(value))) * scale
	return &val
}

// Extractors for 64-bit data types
func extractUint64(value []byte) *uint64 {
	if len(value) >= 8 {
		val := binary.BigEndian.Uint64(value)
		return &val
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

// Extractor for hex representation
func extractHex(value []byte) *string {
	if len(value) > 0 {
		hexValue := fmt.Sprintf("%X", value)
		return &hexValue
	}
	return nil
}
