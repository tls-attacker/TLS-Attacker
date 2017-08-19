/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
import static org.junit.Assert.assertNotSame;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ConnectionEndTest {

    private static final Logger LOGGER = LogManager.getLogger(ConnectionEndTest.class);

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class ConnectionEndRoot extends ConnectionEnd {
    }

    private StringWriter writer;
    private JAXBContext context;
    private Marshaller m;
    private Unmarshaller um;

    @Before
    public void setUp() throws JAXBException {
        writer = new StringWriter();
        context = JAXBContext.newInstance(ConnectionEndRoot.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    /**
     * Verify that the connectionEnd can be serialized properly.
     * 
     * @throws Exception
     */
    @Test
    public void testSerialize() throws Exception {

        ConnectionEndRoot con = new ConnectionEndRoot();
        con.setAlias("testAlias");
        con.setConnectionEndType(ConnectionEndType.CLIENT);

        m.marshal(con, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        ConnectionEndRoot result = (ConnectionEndRoot) um.unmarshal(new StringReader(xmlString));
        ConnectionEndRoot expectedResult = con;

        assertEquals(expectedResult, result);
        assertNotSame(expectedResult, result);
    }

    /**
     * Verify that the connectionEnd does not include unset fields in
     * serialization.
     * 
     * @throws Exception
     */
    @Test
    public void testSerializeEmptyFields() throws Exception {

        ConnectionEndRoot con = new ConnectionEndRoot();

        m.marshal(con, writer);
        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        assertEquals("<connectionEndRoot/>", xmlString.split("\\n")[1]);

        Unmarshaller um = context.createUnmarshaller();
        ConnectionEndRoot result = (ConnectionEndRoot) um.unmarshal(new StringReader(xmlString));
        ConnectionEndRoot expectedResult = con;

        assertEquals(expectedResult, result);
        assertNotSame(expectedResult, result);
    }
}
