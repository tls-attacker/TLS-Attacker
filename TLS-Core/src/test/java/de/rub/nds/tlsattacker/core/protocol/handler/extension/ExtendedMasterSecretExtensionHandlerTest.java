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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ExtendedMasterSecretExtensionHandlerTest {

    private TlsContext context;
    private ExtendedMasterSecretExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ExtendedMasterSecretExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        ExtendedMasterSecretExtensionMessage msg = new ExtendedMasterSecretExtensionMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(msg);

        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isUseExtendedMasterSecret());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(msg);
        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isUseExtendedMasterSecret());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] {}, 0) instanceof ExtendedMasterSecretExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ExtendedMasterSecretExtensionMessage()) instanceof ExtendedMasterSecretExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ExtendedMasterSecretExtensionMessage()) instanceof ExtendedMasterSecretExtensionSerializer);
    }

}
