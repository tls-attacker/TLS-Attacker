/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;


public class ClientConnectionEndTest {

    private static final Logger LOGGER = LogManager.getLogger(ClientConnectionEndTest.class);

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class TestXmlRoot extends ClientConnectionEnd {
    }

    private StringWriter writer;
    private JAXBContext context;
    private Marshaller m;
    private Unmarshaller um;

    @Before
    public void setUp() throws JAXBException {
        writer = new StringWriter();
        context = JAXBContext.newInstance(TestXmlRoot.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    /**
     * Verify that the ClientConnectionEnd can be marshaled and un-marshaled
     * properly.
     * 
     * @throws Exception
     */
    @Test
    public void testSerialize() throws Exception {

        TestXmlRoot expected = new TestXmlRoot();

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    /**
     * Verify that ClientConnectionEnd does not include unset fields in
     * serialization.
     * 
     * @throws Exception
     */
    @Test
    public void testSerializeEmptyFields() throws Exception {

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
     * Verify that ClientConnectionEnd includes manually set values in
     * serialization output.
     * 
     * @throws Exception
     */
    @Test
    public void testSerializeNonDefaultFields() throws Exception {

        TestXmlRoot expected = new TestXmlRoot();
        expected.setAlias("TestMe");
        expected.setHostname("W.X.Y.Z");
        expected.setPort(4444);

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
        sb.append("<testXmlRoot>\n");
        sb.append("    <alias>TestMe</alias>\n");
        sb.append("    <port>4444</port>\n");
        sb.append("    <hostname>W.X.Y.Z</hostname>\n");
        sb.append("</testXmlRoot>\n");
        assertEquals(sb.toString(), xmlString);

        Unmarshaller um = context.createUnmarshaller();
        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    /**
     * Verify that fallback to default values works.
     * 
     * @throws Exception
     */
    @Test
    public void testSetDefaultFields() throws Exception {

        TestXmlRoot conEnd = new TestXmlRoot();
        conEnd.setDefaultTimeout(2300);
        conEnd.setDefaultTransportHandlerType(TransportHandlerType.EAP_TLS);

        assertTrue(conEnd.getTimeout() == 2300);
        assertEquals(conEnd.getTransportHandlerType(), TransportHandlerType.EAP_TLS);

        conEnd.setTimeout(40);
        assertTrue(conEnd.getTimeout() == 40);

        conEnd.setTimeout(null);
        assertTrue(conEnd.getTimeout() == 2300);
    }

    /**
     * Verify that ClientConnectionEnd does not include default values in
     * serialization output.
     * 
     * @throws Exception
     */
    @Test
    public void testSerializeDefaultFields() throws Exception {

        TestXmlRoot expected = new TestXmlRoot();
        expected.setDefaultTimeout(2300);
        expected.setDefaultTransportHandlerType(TransportHandlerType.EAP_TLS);

        m.marshal(expected, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        assertEquals("<testXmlRoot/>", xmlString.split("\\n")[1]);

        Unmarshaller um = context.createUnmarshaller();
        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        // Default values are not marshaled
        assertNotEquals(expected, actual);

        // Default values need to be set again after un-marshaling
        actual.setDefaultTimeout(2300);
        actual.setDefaultTransportHandlerType(TransportHandlerType.EAP_TLS);
        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    /**
     * Verify that ClientConnectionEnd includes overridden defaults in
     * serialization output.
     * 
     * @throws Exception
     */
    @Test
    public void testSerializeOverriddenDefaultFields() throws Exception {

        TestXmlRoot expected = new TestXmlRoot();
        expected.setTimeout(40);
        expected.setTransportHandlerType(TransportHandlerType.UDP);
        m.marshal(expected, writer);

        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
        sb.append("<testXmlRoot>\n");
        sb.append("    <transportHandlerType>UDP</transportHandlerType>\n");
        sb.append("    <timeout>40</timeout>\n");
        sb.append("</testXmlRoot>\n");
        assertEquals(sb.toString(), xmlString);

        Unmarshaller um = context.createUnmarshaller();
        TestXmlRoot actual = (TestXmlRoot) um.unmarshal(new StringReader(xmlString));

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }
}