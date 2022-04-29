/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateStatusRequestExtensionParserTest {
    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload, expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(
            new Object[][] { { ArrayConverter.hexStringToByteArray("0100000000"), 1, 0, new byte[0], 0, new byte[0] },
                { ArrayConverter.hexStringToByteArray("01000102000103"), 1, 1, new byte[] { 0x02 }, 1,
                    new byte[] { 0x03 } } });
    }

    private final byte[] expectedBytes;
    private final int certificateStatusRequestType;
    private final int responderIDListLength;
    private final byte[] responderIDList;
    private final int requestExtensionLength;
    private final byte[] requestExtension;
    private CertificateStatusRequestExtensionParser parser;
    private CertificateStatusRequestExtensionMessage message;
    private final Config config = Config.createConfig();

    public CertificateStatusRequestExtensionParserTest(byte[] expectedBytes, int certificateStatusRequestType,
        int responderIDListLength, byte[] responderIDList, int requestExtensionLength, byte[] requestExtension) {
        this.expectedBytes = expectedBytes;
        this.certificateStatusRequestType = certificateStatusRequestType;
        this.responderIDListLength = responderIDListLength;
        this.responderIDList = responderIDList;
        this.requestExtensionLength = requestExtensionLength;
        this.requestExtension = requestExtension;
    }

    @Before
    public void setUp() {
        TlsContext tlsContext = new TlsContext(config);
        parser = new CertificateStatusRequestExtensionParser(new ByteArrayInputStream(expectedBytes),
            ProtocolVersion.TLS12, tlsContext);
    }

    @Test
    public void testParse() {
        message = new CertificateStatusRequestExtensionMessage();
        parser.parse(message);

        assertEquals(certificateStatusRequestType, (long) message.getCertificateStatusRequestType().getValue());

        assertEquals(responderIDListLength, (long) message.getResponderIDListLength().getValue());
        assertArrayEquals(responderIDList, message.getResponderIDList().getValue());

        assertEquals(requestExtensionLength, (long) message.getRequestExtensionLength().getValue());
        assertArrayEquals(requestExtension, message.getRequestExtension().getValue());
    }
}
