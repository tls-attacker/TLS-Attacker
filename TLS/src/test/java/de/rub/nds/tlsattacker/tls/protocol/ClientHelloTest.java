/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientHelloTest {

    private final StringWriter writer;

    private final JAXBContext context;

    private final Marshaller m;

    private Unmarshaller um;

    public ClientHelloTest() throws Exception {
	writer = new StringWriter();
	context = JAXBContext.newInstance(ExtensionMessage.class, WorkflowTrace.class, ClientHelloMessage.class,
		ModificationFilter.class, IntegerAddModification.class, VariableModification.class,
		ModifiableVariable.class);
	m = context.createMarshaller();
	m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
	m.setAdapter(new ByteArrayAdapter());
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void simpleSerialization() throws JAXBException {
	ClientHelloMessage cl = new ClientHelloMessage();
	cl.setCipherSuiteLength(3);
	// cl.setCipherSuiteLength(new ModifiableInteger());
	cl.getCipherSuiteLength().setModification(new IntegerAddModification(2));
	m.marshal(cl, writer);

	String xmlString = writer.toString();
	System.out.println(xmlString);

	um = context.createUnmarshaller();
	ClientHelloMessage clu = (ClientHelloMessage) um.unmarshal(new StringReader(xmlString));

	writer.append("abcd");
	m.marshal(clu, writer);
	xmlString = writer.toString();
	System.out.println(xmlString);
    }

    @Test
    public void simpleSerialization2() throws Exception {
	ClientCommandConfig config = new ClientCommandConfig();
	WorkflowConfigurationFactory cf = WorkflowConfigurationFactory.createInstance(config);
	TlsContext context = cf.createHandshakeTlsContext();

	m.marshal(context.getWorkflowTrace(), writer);

	String xmlString = writer.toString();
	System.out.println(xmlString);
    }
}
