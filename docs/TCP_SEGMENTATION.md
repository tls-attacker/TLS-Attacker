# TCP Segmentation Feature

## Overview

TLS-Attacker now supports fine-grained control over TCP segmentation, allowing you to split TLS records across multiple TCP segments. This feature enables testing of implementations' handling of fragmented TLS records at the TCP layer.

## Use Cases

- Testing TLS implementations' robustness against fragmented records
- Simulating network conditions where records are split across packets
- Security testing for timing and state handling issues
- Compliance testing for proper reassembly of fragmented data

## Configuration

TCP segmentation is configured per record using the `<tcpSegmentation>` element within a `<Record>` configuration.

### Basic Structure

```xml
<Record>
    <tcpSegmentation>
        <segment>
            <offset>0</offset>
            <length>3</length>
        </segment>
        <segment>
            <offset>3</offset>
        </segment>
        <segmentDelay>10</segmentDelay>
    </tcpSegmentation>
</Record>
```

### Parameters

- **segment**: Defines a single TCP segment
  - **offset**: Starting byte position in the record (0-based)
  - **length**: Number of bytes to include in this segment (optional, defaults to remaining bytes)
- **segmentDelay**: Delay in milliseconds between sending segments (optional, default: 10ms)

## Examples

### Example 1: Split Record Header

Split a TLS record header (5 bytes) across two TCP segments:

```xml
<Send>
    <messages>
        <ClientHello/>
    </messages>
    <records>
        <Record>
            <tcpSegmentation>
                <!-- First 3 bytes: ContentType(1) + Version(2) -->
                <segment>
                    <offset>0</offset>
                    <length>3</length>
                </segment>
                <!-- Remaining: Length(2) + Handshake data -->
                <segment>
                    <offset>3</offset>
                </segment>
                <segmentDelay>10</segmentDelay>
            </tcpSegmentation>
        </Record>
    </records>
</Send>
```

### Example 2: Multiple Segments

Split a record into three segments:

```xml
<Record>
    <tcpSegmentation>
        <!-- Complete header -->
        <segment>
            <offset>0</offset>
            <length>5</length>
        </segment>
        <!-- First 10 bytes of payload -->
        <segment>
            <offset>5</offset>
            <length>10</length>
        </segment>
        <!-- Remaining payload -->
        <segment>
            <offset>15</offset>
        </segment>
        <segmentDelay>5</segmentDelay>
    </tcpSegmentation>
</Record>
```

### Example 3: Programmatic Usage

```java
// Create a record with TCP segmentation
Record record = new Record();
TcpSegmentConfiguration segmentConfig = new TcpSegmentConfiguration();

// Split at byte 3
segmentConfig.addSegment(new TcpSegment(0, 3));
segmentConfig.addSegment(new TcpSegment(3, null));
segmentConfig.setSegmentDelay(10);

record.setTcpSegmentConfiguration(segmentConfig);

// Use in SendAction
SendAction sendAction = new SendAction(message);
sendAction.setConfiguredRecords(List.of(record));
```

## Implementation Details

- Segmentation is applied after record serialization
- Each segment is sent as a separate TCP packet
- Segments are sent in order with configured delays
- Out-of-bounds segments are skipped with a warning
- If no segmentation is configured, records are sent normally

## Transport Handler Support

TCP segmentation works with all TCP-based transport handlers:
- TCP
- TCP_TIMING
- TCP_NO_DELAY
- TCP_FRAGMENTATION (different feature - splits all data uniformly)

## Testing

The feature includes comprehensive unit tests in `TcpSegmentationTest.java` and integration test examples in `TcpSegmentationIT.java`.

## Complete Example

See `resources/examples/tcp_segmentation_example.xml` for a complete workflow demonstrating various TCP segmentation scenarios.
