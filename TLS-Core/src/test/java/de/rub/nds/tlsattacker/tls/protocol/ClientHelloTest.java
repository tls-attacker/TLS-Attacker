/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
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
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientHelloTest {

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
                ModifiableVariable.class, SendAction.class, ReceiveAction.class, TLSAction.class,
                ChangeClientCertificateAction.class, ChangeServerCertificateAction.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.setAdapter(new ByteArrayAdapter());
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void simpleSerialization() throws JAXBException {
        ClientHelloMessage cl = new ClientHelloMessage(new TlsConfig());
        cl.setCipherSuiteLength(3);
        // cl.setCipherSuiteLength(new ModifiableInteger());
        cl.getCipherSuiteLength().setModification(new IntegerAddModification(2));
        try {
            m.marshal(cl, writer);
        } catch (Exception E) {
            E.printStackTrace();
        }
        String xmlString = writer.toString();
        LOGGER.info(xmlString);
        um = context.createUnmarshaller();
        ClientHelloMessage clu = (ClientHelloMessage) um.unmarshal(new StringReader(xmlString));
        writer.append("abcd");
        m.marshal(clu, writer);
        xmlString = writer.toString();
    }

    @Test
    public void simpleSerialization2() throws Exception {
        TlsConfig config = new TlsConfig();
        WorkflowConfigurationFactory cf = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = cf.createFullWorkflow();
        m.marshal(trace, writer);
        String xmlString = writer.toString();
    }

    private static final Logger LOGGER = LogManager.getLogger(ClientHelloTest.class);

}
