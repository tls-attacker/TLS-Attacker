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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
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
public class SignedCertificateTimestampExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int lengthFirstPackage;
    private final byte[] firstTimestamp;
    private final byte[] firstExpectedBytes;
    private final byte[] secondTimestamp;
    private final byte[] secondExpectedBytes;
    private final int lengthSecondPackage;
    private final int startPosition;

    public SignedCertificateTimestampExtensionHandlerTest(ExtensionType extensionType, int lengthFirstPackage,
            byte[] firstTimestamp, byte[] firstExpectedBytes, byte[] secondTimestamp, byte[] secondExpectedBytes,
            int lengthSecondPackage, int startPosition) {
        this.extensionType = extensionType;
        this.lengthFirstPackage = lengthFirstPackage;
        this.firstTimestamp = firstTimestamp;
        this.firstExpectedBytes = firstExpectedBytes;
        this.secondTimestamp = secondTimestamp;
        this.secondExpectedBytes = secondExpectedBytes;
        this.lengthSecondPackage = lengthSecondPackage;
        this.startPosition = startPosition;
    }

    // The secont byte array is a timestamp as found in a ServerHello message.
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {
                ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP,
                0,
                new byte[0],
                ArrayConverter.hexStringToByteArray("00120000"),
                ArrayConverter.hexStringToByteArray("00ef007500ee4bbdb775ce60" + "bae142691fabe19e66a30f7e5fb072d8"
                        + "8300c47b897aa8fdcb0000015b8fdb11" + "14000004030046304402210089716b43"
                        + "ce66822358196424ebae1182ead83b7c" + "126c664528ce222aa2b6e54d021f2377"
                        + "d1be9703495ed3ea3c3e60438381fa08" + "e07713b168ff86091bfec8876d007600"
                        + "ddeb1d2b7a0d4fa6208b81ad8168707e" + "2e8e9d01d55c888d3d11c4cdb6ecbecc"
                        + "0000015b8fdb0fa30000040300473045" + "02210093ede0f0c9b7b1bed787c3a865"
                        + "e35829ab2c9d2cb748afe4181406a689" + "897b4d0220593100bd6728a322a8d440"
                        + "40f2a950c7b99ed4f866ce847bc52606" + "7ef710d303"),
                ArrayConverter.hexStringToByteArray("001200f100ef007500ee4bbdb775ce60"
                        + "bae142691fabe19e66a30f7e5fb072d8" + "8300c47b897aa8fdcb0000015b8fdb11"
                        + "14000004030046304402210089716b43" + "ce66822358196424ebae1182ead83b7c"
                        + "126c664528ce222aa2b6e54d021f2377" + "d1be9703495ed3ea3c3e60438381fa08"
                        + "e07713b168ff86091bfec8876d007600" + "ddeb1d2b7a0d4fa6208b81ad8168707e"
                        + "2e8e9d01d55c888d3d11c4cdb6ecbecc" + "0000015b8fdb0fa30000040300473045"
                        + "02210093ede0f0c9b7b1bed787c3a865" + "e35829ab2c9d2cb748afe4181406a689"
                        + "897b4d0220593100bd6728a322a8d440" + "40f2a950c7b99ed4f866ce847bc52606" + "7ef710d303"), 241,
                0 } });
    }

    @Before
    @Override
    public void setUp() {
        context = new TlsContext();
        handler = new SignedCertificateTimestampExtensionHandler(context);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        SignedCertificateTimestampExtensionMessage messageOne = new SignedCertificateTimestampExtensionMessage();
        messageOne.setSignedTimestamp(firstTimestamp);
        messageOne.setExtensionLength(lengthFirstPackage);

        handler.adjustTLSContext(messageOne);
        assertArrayEquals(firstTimestamp, context.getSignedCertificateTimestamp());

        SignedCertificateTimestampExtensionMessage messageTwo = new SignedCertificateTimestampExtensionMessage();
        messageTwo.setSignedTimestamp(secondTimestamp);
        messageTwo.setExtensionLength(lengthSecondPackage);
        handler.adjustTLSContext(messageTwo);

        assertArrayEquals(secondTimestamp, context.getSignedCertificateTimestamp());
    }

    @Test
    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(firstExpectedBytes, startPosition) instanceof SignedCertificateTimestampExtensionParser);
    }

    @Test
    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SignedCertificateTimestampExtensionMessage()) instanceof SignedCertificateTimestampExtensionPreparator);
    }

    @Test
    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SignedCertificateTimestampExtensionMessage()) instanceof SignedCertificateTimestampExtensionSerializer);
    }
}
