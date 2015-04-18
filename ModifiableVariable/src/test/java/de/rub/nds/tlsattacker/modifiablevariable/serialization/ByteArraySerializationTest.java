/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.modifiablevariable.serialization;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayInsertModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.filter.ModificationFilterFactory;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ByteArraySerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(ByteArraySerializationTest.class);

    private ModifiableByteArray start;

    private byte[] expectedResult, result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    public ByteArraySerializationTest() {
    }

    @Before
    public void setUp() throws JAXBException {
	start = new ModifiableByteArray();
	start.setOriginalValue(new byte[] { 1, 2, 3 });
	expectedResult = null;
	result = null;

	writer = new StringWriter();
	context = JAXBContext.newInstance(ModifiableByteArray.class, ByteArrayDeleteModification.class,
		ByteArrayExplicitValueModification.class, ByteArrayInsertModification.class,
		ByteArrayXorModification.class);
	m = context.createMarshaller();
	m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
	um = context.createUnmarshaller();
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
	start.setModification(null);
	m.marshal(start, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	ModifiableByteArray mba = (ModifiableByteArray) um.unmarshal(new StringReader(xmlString));

	expectedResult = new byte[] { 1, 2, 3 };
	result = mba.getValue();
	assertArrayEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
    }

    @Test
    public void testSerializeDeserializeWithDoubleModification() throws Exception {
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.insert(new byte[] { 1, 2 }, 0);
	VariableModification<byte[]> modifier2 = ByteArrayModificationFactory.insert(new byte[] { 9, 8, 7 }, 3);
	modifier.setPostModification(modifier2);
	start.setModification(modifier);
	m.marshal(start, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	ModifiableByteArray mba = (ModifiableByteArray) um.unmarshal(new StringReader(xmlString));

	expectedResult = new byte[] { 1, 2, 1, 9, 8, 7, 2, 3 };
	result = mba.getValue();
	assertArrayEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

    }

    @Test
    public void testSerializeDeserializeWithDoubleModificationFilter() throws Exception {
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.delete(1, 1);
	int[] filtered = { 1, 3 };
	AccessModificationFilter filter = ModificationFilterFactory.access(filtered);
	modifier.setModificationFilter(filter);
	VariableModification<byte[]> modifier2 = ByteArrayModificationFactory.xor(new byte[] { 1 }, 1);
	modifier.setPostModification(modifier2);
	start.setModification(modifier);
	m.marshal(start, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	ModifiableByteArray mv = (ModifiableByteArray) um.unmarshal(new StringReader(xmlString));

	expectedResult = new byte[] { 1, 2, 3 };
	result = mv.getValue();
	assertArrayEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

	expectedResult = new byte[] { 1, 2 };
	result = mv.getValue();
	assertArrayEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

    }
}
