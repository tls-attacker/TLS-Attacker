/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.modifiablevariable.serialization;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.filter.ModificationFilterFactory;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BigIntegerSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(BigIntegerSerializationTest.class);

    private ModifiableBigInteger start;

    private BigInteger expectedResult, result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    public BigIntegerSerializationTest() {
    }

    @Before
    public void setUp() throws JAXBException {
	start = new ModifiableBigInteger();
	start.setOriginalValue(BigInteger.TEN);
	expectedResult = null;
	result = null;

	writer = new StringWriter();
	context = JAXBContext.newInstance(ModifiableBigInteger.class, BigIntegerAddModification.class,
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
	System.out.println(xmlString);

	um = context.createUnmarshaller();
	ModifiableBigInteger mv = (ModifiableBigInteger) um.unmarshal(new StringReader(xmlString));

	expectedResult = new BigInteger("10");
	result = mv.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
    }

    @Test
    public void testSerializeDeserializeWithDoubleModification() throws Exception {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	VariableModification<BigInteger> modifier2 = BigIntegerModificationFactory.add(BigInteger.ONE);
	modifier.setPostModification(modifier2);
	start.setModification(modifier);
	m.marshal(start, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	ModifiableBigInteger mv = (ModifiableBigInteger) um.unmarshal(new StringReader(xmlString));

	expectedResult = new BigInteger("12");
	result = mv.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

    }

    @Test
    public void testSerializeDeserializeWithDoubleModificationFilter() throws Exception {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	int[] filtered = { 1, 3 };
	AccessModificationFilter filter = ModificationFilterFactory.access(filtered);
	modifier.setModificationFilter(filter);
	VariableModification<BigInteger> modifier2 = BigIntegerModificationFactory.add(BigInteger.ONE);
	modifier.setPostModification(modifier2);
	start.setModification(modifier);
	m.marshal(start, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	ModifiableBigInteger mv = (ModifiableBigInteger) um.unmarshal(new StringReader(xmlString));

	expectedResult = new BigInteger("10");
	result = mv.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

    }

}
