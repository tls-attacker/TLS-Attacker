/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDProtectExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDProtectExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PWDProtectExtensionHandlerTest {
    private PWDProtectExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PWDProtectExtensionHandler(context);
        context.setConnection(new InboundConnection());
    }

    @Test
    public void testAdjustTLSContext() {
        PWDProtectExtensionMessage message = new PWDProtectExtensionMessage();
        message.setUsername(ArrayConverter
                .hexStringToByteArray("DA87739AC04C2A6D222FC15E31C471451DE3FE7E78B6E3485CA21E12BFE1CB4C4191D4CD9257145CBFA26DFCA1839C1588D0F1F6"));
        handler.adjustTLSContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.PWD_PROTECT));
        assertEquals("jens", context.getClientPWDUsername());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof PWDProtectExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PWDProtectExtensionMessage()) instanceof PWDProtectExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PWDProtectExtensionMessage()) instanceof PWDProtectExtensionSerializer);
    }

}