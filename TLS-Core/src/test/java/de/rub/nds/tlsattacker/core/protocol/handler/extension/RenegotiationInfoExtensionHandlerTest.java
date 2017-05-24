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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RenegotiationInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
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
public class RenegotiationInfoExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;

    public RenegotiationInfoExtensionHandlerTest(ExtensionType extensionType, int extensionLength,
            byte[] extensionPayload, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.RENEGOTIATION_INFO, 1, new byte[] { 0 },
                ArrayConverter.hexStringToByteArray("ff01000100"), 0 } });
    }

    @Before
    @Override
    public void setUp() {
        context = new TlsContext();
        handler = new RenegotiationInfoExtensionHandler(context);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setRenegotiationInfo(extensionPayload);
        message.setExtensionLength(extensionLength);
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getRenegotiationInfo(), extensionPayload);
    }

    @Test
    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(expectedBytes, startParsing) instanceof RenegotiationInfoExtensionParser);
    }

    @Test
    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new RenegotiationInfoExtensionMessage()) instanceof RenegotiationInfoExtensionPreparator);
    }

    @Test
    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new RenegotiationInfoExtensionMessage()) instanceof RenegotiationInfoExtensionSerializer);
    }

}
