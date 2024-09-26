# MISB ST 0601 KLV Parser

This repository offers a Go package for parsing MISB ST 0601 (rev 19) KLV metadata streams, a key standard used in the geospatial and intelligence community, especially by organizations like the National Geospatial-Intelligence Agency (NGA). The MISB ST 0601 standard defines a set of metadata elements embedded in video streams from airborne platforms such as drones and reconnaissance aircraft. These elements include critical data such as latitude, longitude, altitude, and mission-specific information.

The parser processes KLV (Key-Length-Value) metadata, an encoding method for transmitting this information. It outputs the structured data in an easy-to-use format, making it suitable for further analysis or conversion into other formats, such as XML, for interoperability with other systems or storage.

## Quick Start Example

1. **Install Golang**:  
   Ensure you have Go (version 1.12 or later) installed. Follow the installation instructions [here](https://go.dev/doc/install).

2. **Download test data**:  
   Download the example data by running the following command:
   ```bash
   wget https://github.com/paretech/klvdata/blob/master/data/DynamicConstantMISMMSPacketData.bin
   ```
3. **Run the example:** 
   Use the test data to run the example code, which prints KLV data as XML:
   ``` bash
   cat DynamicOnlyMISMMSPacketData.bin | go run klvdata/examples/example_print_xml.go 
   ```

### Expected output:
```xml
<KLVTags>
  <Tag ID="1">
    <Name>Checksum</Name>
    <Value>51280</Value>
    <Unit>None</Unit>
  </Tag>
  <Tag ID="2">
    <Name>Precision Time Stamp</Name>
    <Value>1.231798102e+15</Value>
    <Unit>µs</Unit>
  </Tag>
  <Tag ID="5">
    <Name>Platform Heading Angle</Name>
    <Value>159.97436484321355</Value>
    <Unit>°</Unit>
  </Tag>
  <Tag ID="6">
    <Name>Platform Pitch Angle</Name>
    <Value>-0.4315317239906003</Value>
    <Unit>°</Unit>
  </Tag>
</KLVTags>
```


## Step-by-Step Walkthrough
### 1. Capturing the KLV Stream Using FFmpeg

You can capture KLV metadata either from a live UDP stream or from a recorded file. The following steps explain how to use `ffmpeg` to pipe the KLV stream into the parser.

### 2. Parsing KLV from a UDP Stream

If the KLV metadata is coming from a live UDP stream, use the following `ffmpeg` command to pipe the KLV stream directly into the parser:

```bash
ffmpeg -i udp://127.0.0.1:4444 -map 0:1 -c copy -f data pipe: | ./your_parser_executable
```

In this command:

- `udp://127.0.0.1:4444` is the source of the KLV stream.
- `map 0:1` selects the relevant channel containing the KLV metadata.
- `pipe:` directs the KLV stream to standard input for further processing.

### 3. Parsing KLV from a File

If you have a recorded file containing KLV data, you can use the following `ffmpeg` command to extract the KLV stream from the file and pipe it into the parser:

```bash
ffmpeg -i input_file.ts -map 0:1 -c copy -f data pipe: | ./your_parser_executable
```

In this command:
- `input_file.ts` is the input file containing the KLV metadata.
- `map 0:1` selects the relevant channel containing the KLV metadata from the file.
- `pipe:` directs the KLV data to the parser for further processing.


### 4. Running the Example to Print KLV Tags as XML

In this step, we will walk through how to use the example provided in the examples/ folder to read KLV data (either from a live UDP stream or a file) and output it in an easy-to-read XML format.
#### 4.1. Setting Up the Example

Before running the example, make sure you have the necessary Go environment set up. If you haven't installed Go yet, you can download it from the official website: https://golang.org/dl/.

After installing Go, navigate to the folder where your KLV parser project is located (typically, this will be the root directory of your project). From this directory, you will be able to build and run the example program.
#### 4.2. Parsing a Live UDP Stream

If your KLV data comes from a live stream (for example, a video feed that also contains KLV metadata), you can follow these steps:
1. Use the `ffmpeg` tool to capture the KLV data from the stream.
2. Pipe this data into the example program that outputs the KLV tags as XML.

Run the following command in your terminal:
```bash
ffmpeg -i udp://127.0.0.1:4444 -map 0:1 -c copy -f data pipe: | go run examples/example_print_xml.go
```
#### 4.3. Parsing KLV Data from a File

If you already have a file that contains KLV data, you can use the example program to read the file and output the KLV data as XML.

1. Use the ffmpeg tool to extract the KLV metadata from the file.
2. Pipe the data into the example program.

```bash
ffmpeg -i input_file.ts -map 0:1 -c copy -f data pipe: | go run examples/example_print_xml.go
```





### 5. Output Example
The XML output will look something like this:
```xml
<KLVTags>
  <Tag ID="1" Name="Checksum" Value="12345" />
  <Tag ID="2" Name="Timestamp" Value="1620384000000" Unit="µs" />
  <Tag ID="5" Name="Platform Heading" Value="270.0" Unit="°" />
  ...
</KLVTags>
```

### Key Features

- Parses MISB ST 0601 (rev 19) metadata streams.
- Outputs structured KLV tags, including tag ID, name, value, and unit (if applicable).
- Can process KLV data from both live UDP streams and recorded files.

For detailed usage instructions, please refer to the provided example in the examples/ directory.
