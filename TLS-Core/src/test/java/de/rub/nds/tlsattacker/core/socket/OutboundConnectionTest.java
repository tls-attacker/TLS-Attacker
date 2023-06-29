/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.socket;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.StringReader;
import java.io.StringWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OutboundConnectionTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private StringWriter writer;
    private JAXBContext context;
    private Marshaller m;
    private Unmarshaller um;

    @BeforeEach
    public void setUp() throws JAXBException {
        writer = new StringWriter();
        context = JAXBContext.newInstance(TestXmlRoot.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    @Test
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() throws JAXBException {

        TestXmlRoot expected = new TestXmlRoot();

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    @Test
    public void marshalingEmptyActionYieldsMinimalOutput() throws JAXBException {

        TestXmlRoot expected = new TestXmlRoot();

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        assertEquals("<testXmlRoot/>", xmlString.split("\\n")[1]);

        Unmarshaller um = context.createUnmarshaller();
        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    /**
     * Verify that the ServerConnectionEnd includes manually set values in serialization output.
     *
     * @throws Exception
     */
    @Test
    public void testSerializeNonDefaultFields() throws JAXBException {

        TestXmlRoot expected = new TestXmlRoot();
        expected.setAlias("TestMe");
        expected.setPort(4444);

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        String sb =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
                        + "<testXmlRoot>\n"
                        + "    <alias>TestMe</alias>\n"
                        + "    <port>4444</port>\n"
                        + "</testXmlRoot>\n";
        assertEquals(sb, xmlString);

        Unmarshaller um = context.createUnmarshaller();
        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    @Test
    public void mixInDefaultsFromReference() {

        TestXmlRoot con = new TestXmlRoot();
        OutboundConnection defaultCon = new OutboundConnection();

        defaultCon.setPort(9772);
        defaultCon.setTimeout(2300);
        defaultCon.setTransportHandlerType(TransportHandlerType.EAP_TLS);
        defaultCon.setHostname("testDefaultHost");
        defaultCon.setAlias("testDefaultAlias");

        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());

        con.normalize(defaultCon);
        assertEquals(2300, con.getTimeout().intValue());
        assertSame(TransportHandlerType.EAP_TLS, con.getTransportHandlerType());
        assertEquals("testDefaultHost", con.getHostname());
        assertEquals("testDefaultAlias", con.getAlias());
        assertEquals(9772, con.getPort().intValue());
    }

    @Test
    public void mixInDefaultsFromEmptyReference() {
        TestXmlRoot con = new TestXmlRoot();
        OutboundConnection defaultCon = new OutboundConnection();

        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());

        con.normalize(null);
        assertEquals(OutboundConnection.DEFAULT_TIMEOUT, con.getTimeout());
        assertSame(
                OutboundConnection.DEFAULT_TRANSPORT_HANDLER_TYPE, con.getTransportHandlerType());
        assertEquals(OutboundConnection.DEFAULT_HOSTNAME, con.getHostname());
        assertEquals(OutboundConnection.DEFAULT_CONNECTION_ALIAS, con.getAlias());
        assertEquals(OutboundConnection.DEFAULT_PORT, con.getPort());
    }

    @Test
    public void stripDefaultsReversesMixInEmptyDefaults() {
        TestXmlRoot con = new TestXmlRoot();
        OutboundConnection defaultCon = new OutboundConnection();

        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());

        con.normalize(null);
        assertEquals(OutboundConnection.DEFAULT_TIMEOUT, con.getTimeout());
        assertSame(
                OutboundConnection.DEFAULT_TRANSPORT_HANDLER_TYPE, con.getTransportHandlerType());
        assertEquals(OutboundConnection.DEFAULT_HOSTNAME, con.getHostname());
        assertEquals(OutboundConnection.DEFAULT_CONNECTION_ALIAS, con.getAlias());
        assertEquals(OutboundConnection.DEFAULT_PORT, con.getPort());

        con.filter(null);
        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());
    }

    @Test
    public void stripDefaultsReversesMixInDefaults() {

        TestXmlRoot con = new TestXmlRoot();
        OutboundConnection defaultCon = new OutboundConnection();

        defaultCon.setPort(9772);
        defaultCon.setTimeout(2300);
        defaultCon.setTransportHandlerType(TransportHandlerType.EAP_TLS);
        defaultCon.setHostname("testDefaultHost");
        defaultCon.setAlias("testDefaultAlias");

        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());

        con.normalize(defaultCon);
        assertEquals(2300, con.getTimeout().intValue());
        assertSame(TransportHandlerType.EAP_TLS, con.getTransportHandlerType());
        assertEquals("testDefaultHost", con.getHostname());
        assertEquals("testDefaultAlias", con.getAlias());
        assertEquals(9772, con.getPort().intValue());

        con.filter(defaultCon);
        assertNull(con.getTimeout());
        assertNull(con.getTransportHandlerType());
        assertNull(con.getHostname());
        assertNull(con.getAlias());
        assertNull(con.getPort());
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class TestXmlRoot extends OutboundConnection {}
}
