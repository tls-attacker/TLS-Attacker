/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.serialization;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.filter.ModificationFilterFactory;
import de.rub.nds.tlsattacker.modifiablevariable.mlong.LongAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.mlong.LongModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.mlong.ModifiableLong;
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
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class LongSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(LongSerializationTest.class);

    private ModifiableLong start;

    private Long expectedResult, result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    public LongSerializationTest() {
    }

    @Before
    public void setUp() throws JAXBException {
        start = new ModifiableLong();
        start.setOriginalValue(10L);
        expectedResult = null;
        result = null;

        writer = new StringWriter();
        context = JAXBContext.newInstance(ModifiableLong.class, LongAddModification.class,
                ByteArrayModificationFactory.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
        start.setModification(null);
        m.marshal(start, writer);

        String xmlString = writer.toString();
        LOGGER.info(xmlString);

        um = context.createUnmarshaller();
        ModifiableLong mv = (ModifiableLong) um.unmarshal(new StringReader(xmlString));

        expectedResult = 10L;
        result = mv.getValue();
        assertEquals(expectedResult, result);

    }

    @Test
    public void testSerializeDeserializeWithDoubleModification() throws Exception {
        VariableModification<Long> modifier = LongModificationFactory.add(1L);
        VariableModification<Long> modifier2 = LongModificationFactory.add(1L);
        modifier.setPostModification(modifier2);
        start.setModification(modifier);
        m.marshal(start, writer);

        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        um = context.createUnmarshaller();
        ModifiableLong mv = (ModifiableLong) um.unmarshal(new StringReader(xmlString));

        expectedResult = 12L;
        result = mv.getValue();
        assertEquals(expectedResult, result);

    }

    @Test
    public void testSerializeDeserializeWithDoubleModificationFilter() throws Exception {
        VariableModification<Long> modifier = LongModificationFactory.add(1L);
        int[] filtered = { 1, 3 };
        AccessModificationFilter filter = ModificationFilterFactory.access(filtered);
        modifier.setModificationFilter(filter);
        VariableModification<Long> modifier2 = LongModificationFactory.add(1L);
        modifier.setPostModification(modifier2);
        start.setModification(modifier);
        m.marshal(start, writer);

        String xmlString = writer.toString();
        LOGGER.debug(xmlString);

        um = context.createUnmarshaller();
        ModifiableLong mv = (ModifiableLong) um.unmarshal(new StringReader(xmlString));

        expectedResult = 10L;
        result = mv.getValue();
        assertEquals(expectedResult, result);

    }

}
