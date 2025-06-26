/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tcp;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.tcp.TcpSegmentConfiguration.TcpSegment;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;

public class TcpSegmentConfigurationTest {

    @Test
    public void testTcpSegmentConfiguration() {
        TcpSegmentConfiguration config = new TcpSegmentConfiguration();

        // Test adding segments
        config.addSegment(new TcpSegment(0, 3));
        config.addSegment(new TcpSegment(3, 10));
        config.setSegmentDelay(15);

        assertEquals(2, config.getSegments().size());
        assertEquals(0, config.getSegments().get(0).getOffset().intValue());
        assertEquals(3, config.getSegments().get(0).getLength().intValue());
        assertEquals(3, config.getSegments().get(1).getOffset().intValue());
        assertEquals(10, config.getSegments().get(1).getLength().intValue());
        assertEquals(15, config.getSegmentDelay().intValue());
    }

    @Test
    public void testTcpSegmentConfigurationSerialization() throws JAXBException {
        // Create configuration
        TcpSegmentConfiguration config = new TcpSegmentConfiguration();
        config.addSegment(new TcpSegment(0, 5));
        config.addSegment(new TcpSegment(5, null));
        config.setSegmentDelay(20);

        // Serialize to XML
        JAXBContext context = JAXBContext.newInstance(TcpSegmentConfiguration.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter writer = new StringWriter();
        marshaller.marshal(config, writer);
        String xml = writer.toString();

        // Verify XML contains expected elements
        assertTrue(xml.contains("<tcpSegmentConfiguration>"));
        assertTrue(xml.contains("<segment>"));
        assertTrue(xml.contains("<offset>0</offset>"));
        assertTrue(xml.contains("<length>5</length>"));
        assertTrue(xml.contains("<offset>5</offset>"));
        assertTrue(xml.contains("<segmentDelay>20</segmentDelay>"));

        // Deserialize from XML
        Unmarshaller unmarshaller = context.createUnmarshaller();
        TcpSegmentConfiguration deserialized =
                (TcpSegmentConfiguration) unmarshaller.unmarshal(new StringReader(xml));

        // Verify deserialized object
        assertNotNull(deserialized);
        assertEquals(2, deserialized.getSegments().size());
        assertEquals(0, deserialized.getSegments().get(0).getOffset().intValue());
        assertEquals(5, deserialized.getSegments().get(0).getLength().intValue());
        assertEquals(5, deserialized.getSegments().get(1).getOffset().intValue());
        assertNull(deserialized.getSegments().get(1).getLength());
        assertEquals(20, deserialized.getSegmentDelay().intValue());
    }

    @Test
    public void testEmptyConfiguration() {
        TcpSegmentConfiguration config = new TcpSegmentConfiguration();
        assertNotNull(config.getSegments());
        assertTrue(config.getSegments().isEmpty());
        assertEquals(10, config.getSegmentDelay().intValue()); // Default value
    }

    @Test
    public void testTcpSegment() {
        TcpSegment segment = new TcpSegment(10, 20);
        assertEquals(10, segment.getOffset().intValue());
        assertEquals(20, segment.getLength().intValue());

        segment.setOffset(15);
        segment.setLength(25);
        assertEquals(15, segment.getOffset().intValue());
        assertEquals(25, segment.getLength().intValue());
    }
}
