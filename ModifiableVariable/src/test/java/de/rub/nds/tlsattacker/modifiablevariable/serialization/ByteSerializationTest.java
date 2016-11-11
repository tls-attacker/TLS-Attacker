/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.serialization;

import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ByteSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(ByteSerializationTest.class);

    private ModifiableByte start;

    private Byte expectedResult, result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    public ByteSerializationTest() {
    }

    @Before
    public void setUp() throws JAXBException {
        start = new ModifiableByte();
        start.setOriginalValue((byte) 10);

        writer = new StringWriter();
        context = JAXBContext.newInstance(ModifiableByte.class, ByteAddModification.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
        start.setModification(null);
        m.marshal(start, writer);

        String xmlString = writer.toString();
        System.out.println(xmlString);

        um = context.createUnmarshaller();
        ModifiableByte mv = (ModifiableByte) um.unmarshal(new StringReader(xmlString));

        expectedResult = 10;
        result = mv.getValue();
        assertEquals(expectedResult, result);
    }

    @Test
    public void testSerializeDeserializeWithDoubleModification() throws Exception {
        // TODO

    }

    @Test
    public void testSerializeDeserializeWithDoubleModificationFilter() throws Exception {
        // TODO

    }
}
