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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TruncatedHmacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TruncatedHmacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TruncatedHmacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TruncatedHmacExtensionHandlerTest {

    private TruncatedHmacExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new TruncatedHmacExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        TruncatedHmacExtensionMessage message = new TruncatedHmacExtensionMessage();
        handler.adjustTLSContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.TRUNCATED_HMAC));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof TruncatedHmacExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new TruncatedHmacExtensionMessage()) instanceof TruncatedHmacExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new TruncatedHmacExtensionMessage()) instanceof TruncatedHmacExtensionSerializer);
    }
}
