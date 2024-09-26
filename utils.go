package klvparser

import (
	"log"
)

// tolerance is used for floating-point comparisons to account for minor precision errors.
// This constant helps to avoid issues due to the inherent imprecision of floating-point arithmetic.
const tolerance = 0.00001

// Check if the value is within the bounds defined in tagMeta.
func checkBounds(tag int, value float64) bool {
	meta, ok := tagMeta[tag]
	if !ok {
		log.Printf("No metadata for tag %d\n", tag)
		return false
	}
	if value < meta.MinValue-tolerance || value > meta.MaxValue+tolerance {
		log.Printf("Warning: Value for tag %d (%s) is out of bounds: %f (allowed: %f - %f)\n",
			tag, meta.Name, value, meta.MinValue, meta.MaxValue)
		return false
	}
	return true
}

// Process a tag's value by checking bounds and assigning it to the tag.
func processValue(tag int, value []byte, extractor func([]byte) *float64) {
	meta := tagMeta[tag]
	if meta == nil {
		log.Printf("Warning: Unknown tag or uninitialized metadata for tag: %d\n", tag)
		return
	}
	extractedValue := extractor(value)
	if extractedValue == nil {
		log.Printf("Warning: Failed to extract value for tag %d (%s)\n", tag, meta.Name)
		return
	}
	if !checkBounds(tag, *extractedValue) {
		log.Printf("Warning: Tag %d (%s) value %f does not comply with bounds.\n", tag, meta.Name, *extractedValue)
		return
	}
	meta.Value = *extractedValue
}

// extractTagValue extracts the value of a tag from the byte array.
func (p *KLVParser) extractTagValue(valueBytes []byte, index int) (int, []byte, int) {
	if len(valueBytes) <= index {
		return 0, nil, index
	}
	lengthByte := valueBytes[index]
	index++

	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		lengthSize := int(lengthByte & 0x7F)
		if len(valueBytes) < index+lengthSize {
			return 0, nil, index
		}
		length = 0
		for i := 0; i < lengthSize; i++ {
			length = (length << 8) | int(valueBytes[index+i])
		}
		index += lengthSize
	}
	if len(valueBytes) < index+length {
		return 0, nil, index
	}
	tagValue := valueBytes[index : index+length]
	index += length
	return length, tagValue, index
}

// extractKLVPacket extracts a KLV packet from the data buffer.
func (p *KLVParser) extractKLVPacket(data []byte) ([]byte, []byte, error) {
	if len(data) < 17 {
		return nil, data, nil
	}

	packetLength, lengthFieldSize := p.calculatePacketLength(data)
	totalPacketSize := 16 + lengthFieldSize + int(packetLength)

	if len(data) < totalPacketSize {
		return nil, data, nil
	}

	return data[:totalPacketSize], data[totalPacketSize:], nil
}

// calculatePacketLength calculates the length of a KLV packet.
func (p *KLVParser) calculatePacketLength(data []byte) (uint64, int) {
	lengthByte := data[16]
	if lengthByte&0x80 == 0 {
		return uint64(lengthByte), 1
	}
	lengthFieldSize := int(lengthByte & 0x7F)
	lengthBytes := data[17 : 17+lengthFieldSize]
	packetLength := uint64(0)
	for _, b := range lengthBytes {
		packetLength = (packetLength << 8) | uint64(b)
	}
	return packetLength, lengthFieldSize
}

// getValueStartAndLength returns the start index and length of a KLV packet's value.
func (p *KLVParser) getValueStartAndLength(klvPacket []byte) (int, int) {
	lengthByte := klvPacket[16]
	if lengthByte&0x80 == 0 {
		return 17, int(lengthByte)
	}

	lengthSize := int(lengthByte & 0x7F)
	length := 0
	for i := 0; i < lengthSize; i++ {
		length = (length << 8) | int(klvPacket[17+i])
	}
	return 17 + lengthSize, length
}
