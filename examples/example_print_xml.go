package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"github.com/StefanGrimminck/klvparser"
	"io"
	"os"
	"sort"
)

// XMLTag represents the structure for printing KLV tags as XML.
type XMLTag struct {
	XMLName xml.Name `xml:"Tag"`
	ID      int      `xml:"ID,attr"`
	Name    string   `xml:"Name"`
	Value   string   `xml:"Value"`
	Unit    string   `xml:"Unit,omitempty"` // Include Unit in XML output if available
}

// printKLVTags takes parsed KLV tags and prints them as an XML structure.
func printKLVTags(parsedTags map[int]*klvparser.KLVTag) {
	var xmlTags []XMLTag
	var tagKeys []int

	// Collect all the tag keys
	for tag := range parsedTags {
		tagKeys = append(tagKeys, tag)
	}

	// Sort tags by ID
	sort.Ints(tagKeys)

	// Create XMLTag structs for each KLV tag
	for _, tag := range tagKeys {
		tagData := parsedTags[tag]
		if tagData.Value != nil {
			xmlTag := XMLTag{
				ID:    tag,
				Name:  tagData.Name,
				Value: fmt.Sprintf("%v", tagData.Value),
				Unit:  tagData.Unit, // Include unit in the XML output
			}
			xmlTags = append(xmlTags, xmlTag)
		}
	}

	// Marshal the tags into XML format
	output, err := xml.MarshalIndent(struct {
		XMLName xml.Name `xml:"KLVTags"`
		Tags    []XMLTag `xml:"Tag"`
	}{Tags: xmlTags}, "", "  ")

	if err != nil {
		fmt.Println("Error generating XML:", err)
		return
	}

	// Print the XML output
	fmt.Println(string(output))
}

func main() {
	// Initialize the KLVParser with a callback to print the parsed tags as XML
	parser := klvparser.NewKLVParser(func(parsedTags map[int]*klvparser.KLVTag) {
		printKLVTags(parsedTags)
	})

	// Reading data from stdin (or you can replace with a file reader)
	reader := bufio.NewReader(os.Stdin)

	for {
		// Buffer size for reading chunks
		chunk := make([]byte, 1024)

		// Read a chunk of data
		n, err := reader.Read(chunk)
		if err != nil {
			if err == io.EOF {
				fmt.Println("End of input stream.")
				break
			}
			fmt.Println("Error reading input:", err)
			return
		}

		// Process the chunk with the KLV parser
		err = parser.ProcessChunk(chunk[:n])
		if err != nil {
			fmt.Println("Error processing chunk:", err)
			return
		}
	}
}
