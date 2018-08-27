/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModificationFilter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClientHelloTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    private final StringWriter writer;

    private final JAXBContext context;

    private final Marshaller m;

    private Unmarshaller um;

    public ClientHelloTest() throws Exception {
        writer = new StringWriter();
        context = JAXBContext.newInstance(ExtensionMessage.class, WorkflowTrace.class, ClientHelloMessage.class,
                ModificationFilter.class, IntegerAddModification.class, VariableModification.class,
                ModifiableVariable.class, SendAction.class, ReceiveAction.class, TlsAction.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.setAdapter(new ByteArrayAdapter());
    }

    @Before
    public void setUp() {
        // TODO constructor cleaning
        // writer, context, m must be final?
    }

    @After
    public void tearDown() {
    }

    /**
     * TODO: refactor this test, proper test name, make code readable...
     *
     * @throws JAXBException
     */
    @Test
    public void simpleSerialization() throws JAXBException {
        ClientHelloMessage cl = new ClientHelloMessage(Config.createConfig());
        cl.setCipherSuiteLength(3);
        // cl.setCipherSuiteLength(new ModifiableInteger());
        cl.getCipherSuiteLength().setModification(new IntegerAddModification(2));
        try {
            m.marshal(cl, writer);
        } catch (JAXBException E) {
            fail();
        }
        String xmlString = writer.toString();
        LOGGER.info(xmlString);
        um = context.createUnmarshaller();
        ClientHelloMessage clu = (ClientHelloMessage) um.unmarshal(new StringReader(xmlString));
        writer.append("abcd");
        m.marshal(clu, writer);
        xmlString = writer.toString();
        assertNotNull(xmlString);
    }

    /**
     * TODO: give test a proper name
     *
     * @throws JAXBException
     */
    @Test
    public void simpleSerialization2() throws Exception {
        WorkflowConfigurationFactory cf = new WorkflowConfigurationFactory(Config.createConfig());
        WorkflowTrace trace = cf.createWorkflowTrace(WorkflowTraceType.FULL, RunningModeType.CLIENT);
        m.marshal(trace, writer);
        String xmlString = writer.toString();
        assertNotNull(xmlString);
    }

    @Test
    public void testToString() {
        ClientHelloMessage message = new ClientHelloMessage();
        StringBuilder sb = new StringBuilder();

        sb.append("ClientHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Client Unix Time: ").append("null");
        sb.append("\n  Client Random: ").append("null");
        sb.append("\n  Session ID: ").append("null");
        sb.append("\n  Supported Cipher Suites: ").append("null");
        sb.append("\n  Supported Compression Methods: ").append("null");
        sb.append("\n  Extensions: ").append("null");
        Assert.assertEquals(message.toString(), sb.toString());
    }

}
