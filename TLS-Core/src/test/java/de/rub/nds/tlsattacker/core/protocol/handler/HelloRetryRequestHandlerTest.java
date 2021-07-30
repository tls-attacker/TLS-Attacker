/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

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
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof HelloRetryRequestParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new HelloRetryRequestMessage()) instanceof HelloRetryRequestPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new HelloRetryRequestMessage()) instanceof HelloRetryRequestSerializer);
    }

    @Test
    public void testAdjustTLSContext() {
        HelloRetryRequestMessage message = new HelloRetryRequestMessage();
        ExtensionMessage extensionMessage = new EncryptThenMacExtensionMessage();
        ProtocolVersion protocolVersion = ProtocolVersion.SSL2;
        CipherSuite cipherSuite = CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA;
        ExtensionType extensionType = ExtensionType.ENCRYPT_THEN_MAC;

        message.setProtocolVersion(protocolVersion.getValue());
        message.setSelectedCipherSuite(cipherSuite.getByteValue());
        message.setExtensionBytes(extensionType.getValue());
        message.addExtension(extensionMessage);

        handler.adjustTLSContext(message);
        assertSame(context.getSelectedProtocolVersion(), protocolVersion);
        assertSame(context.getSelectedCipherSuite(), cipherSuite);
        assertTrue(context.isExtensionProposed(extensionType));
    }

}
