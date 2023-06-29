/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModificationFilter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;

public class ClientHelloMessageTest extends AbstractMessageTest<ClientHelloMessage> {

    private static Marshaller m;

    private static Unmarshaller um;

    private final StringWriter writer;

    public ClientHelloMessageTest() {
        super(
                ClientHelloMessage::new,
                "ClientHelloMessage:\n"
                        + "  Protocol Version: %s\n"
                        + "  Client Unix Time: %s\n"
                        + "  Client Random: %s\n"
                        + "  Session ID: %s\n"
                        + "  Supported Cipher Suites: %s\n"
                        + "  Supported Compression Methods: %s\n"
                        + "  Extensions: %s");
        writer = new StringWriter();
    }

    @BeforeAll
    public static void setUpClass() throws JAXBException {
        JAXBContext context =
                JAXBContext.newInstance(
                        ExtensionMessage.class,
                        WorkflowTrace.class,
                        ClientHelloMessage.class,
                        ModificationFilter.class,
                        IntegerAddModification.class,
                        VariableModification.class,
                        ModifiableVariable.class,
                        SendAction.class,
                        ReceiveAction.class,
                        TlsAction.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.setAdapter(new UnformattedByteArrayAdapter());
        um = context.createUnmarshaller();
    }

    @Test
    public void testClientHelloSerialization() throws JAXBException {
        ClientHelloMessage cl = new ClientHelloMessage(Config.createConfig());
        cl.setCipherSuiteLength(3);
        cl.getCipherSuiteLength().setModification(new IntegerAddModification(2));
        try {
            m.marshal(cl, writer);
        } catch (JAXBException E) {
            fail();
        }
        String xmlString = writer.toString();
        ClientHelloMessage clu = (ClientHelloMessage) um.unmarshal(new StringReader(xmlString));
        writer.append("abcd");
        m.marshal(clu, writer);
        xmlString = writer.toString();
        assertNotNull(xmlString);
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        return Stream.of(
                Arguments.of(new Object[] {null, null, null, null, null, null, null}, null));
    }
}
