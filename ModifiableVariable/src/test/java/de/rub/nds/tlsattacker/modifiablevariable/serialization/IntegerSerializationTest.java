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

import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class IntegerSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(IntegerSerializationTest.class);

    private ModifiableInteger start;

    private int expectedResult, result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    public IntegerSerializationTest() {
    }

    @Before
    public void setUp() throws JAXBException {
	// todo
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
	// TODO
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
