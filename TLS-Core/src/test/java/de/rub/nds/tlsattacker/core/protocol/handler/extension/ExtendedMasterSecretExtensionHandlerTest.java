/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
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

        handler.adjustTLSContext(msg);

        assertTrue(context.isExtendedMasterSecretExtension());

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
