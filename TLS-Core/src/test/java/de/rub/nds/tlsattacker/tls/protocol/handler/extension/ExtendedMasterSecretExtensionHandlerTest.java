/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializerTest;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] expectedBytes;
    private final int startParsing;

    public ExtendedMasterSecretExtensionHandlerTest(ExtensionType extensionType, int extensionLength, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ExtendedMasterSecretExtensionSerializerTest.generateData();
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ExtendedMasterSecretExtensionHandler(context);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        ExtendedMasterSecretExtensionMessage msg = new ExtendedMasterSecretExtensionMessage();

        handler.adjustTLSContext(msg);

        assertTrue(context.isExtendedMasterSecret());

    }

    @Test
    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(expectedBytes, startParsing) instanceof ExtendedMasterSecretExtensionParser);
    }

    @Test
    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ExtendedMasterSecretExtensionMessage()) instanceof ExtendedMasterSecretExtensionPreparator);
    }

    @Test
    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ExtendedMasterSecretExtensionMessage()) instanceof ExtendedMasterSecretExtensionSerializer);
    }

}
