/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import org.junit.Before;
import org.junit.Test;
import java.util.List;

import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;


import static org.junit.Assert.*;

public class HelloRetryRequestHandlerTest {
    private TlsContext context;
    private HelloRetryRequestHandler handler;


    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HelloRetryRequestHandler(context);
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
        HelloRetryRequestMessage message = new HelloRetryRequestMessage();
        ProtocolVersion protocolVersion = ProtocolVersion.SSL2;
        CipherSuite cipherSuite = CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA;
        ExtensionType extensionType = ExtensionType.SERVER_NAME_INDICATION;
        List<ExtensionMessage> extensionMessages = MessageFactory.generateExtensionMessages();

        message.setProtocolVersion(protocolVersion.getValue());
        message.setSelectedCipherSuite(cipherSuite.getByteValue());
        message.setExtensionBytes(extensionType.getValue());

        message.addExtension(extensionMessages.get(0));

        handler.adjustTLSContext(message);
        ExtensionType type = ExtensionType.getExtensionType(message.getExtensions().get(0).getExtensionTypeConstant().getValue());


        assertSame(context.getSelectedProtocolVersion(),protocolVersion);
        assertSame(context.getSelectedCipherSuite(), cipherSuite);
        assertEquals(context.getProposedExtensions().toString(),"["+type+"]");

        if(context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT){
            assertTrue(context.isExtensionProposed(type));
        }else if(context.getTalkingConnectionEndType() == ConnectionEndType.SERVER){
            assertTrue(context.isExtensionNegotiated(type));
        }

    }

}
