/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class EncryptThenMacExtensionHandlerTest {
    private EncryptThenMacExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new EncryptThenMacExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        EncryptThenMacExtensionMessage message = new EncryptThenMacExtensionMessage();
        handler.adjustTLSContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.ENCRYPT_THEN_MAC));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof EncryptThenMacExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new EncryptThenMacExtensionMessage()) instanceof EncryptThenMacExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new EncryptThenMacExtensionMessage()) instanceof EncryptThenMacExtensionSerializer);
    }
}
