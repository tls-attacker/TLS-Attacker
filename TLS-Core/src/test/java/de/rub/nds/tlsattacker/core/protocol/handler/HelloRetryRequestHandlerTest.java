/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.junit.Test;
import java.util.List;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;


import static org.junit.Assert.*;

public class HelloRetryRequestHandlerTest {
    private TlsContext context = new TlsContext();
    private HelloRetryRequestHandler handler = new HelloRetryRequestHandler(context);

    //@Before
    public void setUp() {

    }

    @Test
    public void testGetParser(){
        assertTrue(handler.getParser(new byte[1], 0) instanceof HelloRetryRequestParser);
    }

    @Test
    public void testGetPreparator(){
        assertTrue(handler.getPreparator(new HelloRetryRequestMessage()) instanceof HelloRetryRequestPreparator);
    }

    @Test
    public void testGetSerializer(){
        assertTrue(handler.getSerializer(new HelloRetryRequestMessage()) instanceof HelloRetryRequestSerializer);
    }

    @Test
    public void testAdjustTLSContext(){
        List<ExtensionMessage> extensionMessages = MessageFactory.generateExtensionMessages();
        HelloRetryRequestMessage message = new HelloRetryRequestMessage();

        message.setProtocolVersion(new byte[] { (byte) 0x00, (byte) 0x02 });
        message.setSelectedCipherSuite(new byte[]{(byte) 0x0C});
        message.setExtensionBytes(new byte[] { (byte) 0, (byte) 0 });
        message.addExtension(extensionMessages.get(0));


        handler.adjustTLSContext(message);
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        CipherSuite suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        ExtensionType type = ExtensionType.getExtensionType(message.getExtensions().get(0).getExtensionTypeConstant().getValue());


        assertSame(context.getSelectedProtocolVersion(), version);
        assertSame(context.getSelectedCipherSuite(), suite);
        assertEquals(context.getProposedExtensions().toString(), "["+type+"]");

    }

    //@After
    public void tearDown() {

    }
}