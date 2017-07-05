/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SrtpExtensionParserTest {

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int startParsing;
    private final int srtpProtectionProfilesLength;
    private final byte[] srtpProtectionProfiles;
    private final int srtpMkiLength;
    private final byte[] srtpMki;
    private SrtpExtensionParser parser;
    private SrtpExtensionMessage msg;

    public SrtpExtensionParserTest(ExtensionType extensionType, byte[] expectedBytes, int extensionLength,
            int startParsing, int srtpProtectionProfilesLength, byte[] srtpProtectionProfiles, int srtpMkiLength,
            byte[] srtpMki) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.srtpProtectionProfilesLength = srtpProtectionProfilesLength;
        this.srtpProtectionProfiles = srtpProtectionProfiles;
        this.srtpMkiLength = srtpMkiLength;
        this.srtpMki = srtpMki;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ExtensionType.USE_SRTP, ArrayConverter.hexStringToByteArray("000e0009000400010006020102"), 9, 0, 4,
                        ArrayConverter.hexStringToByteArray("00010006"), 2, new byte[] { 0x01, 0x02 } },
                { ExtensionType.USE_SRTP, ArrayConverter.hexStringToByteArray("000e000900040001000600"), 9, 0, 4,
                        ArrayConverter.hexStringToByteArray("00010006"), 0, new byte[] {} } });
    }

    @Before
    public void setUp() {
        parser = new SrtpExtensionParser(startParsing, expectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        msg = parser.parse();

        assertArrayEquals(extensionType.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (int) msg.getExtensionLength().getValue());

        assertArrayEquals(srtpProtectionProfiles, msg.getSrtpProtectionProfiles().getValue());
        assertEquals(srtpProtectionProfilesLength, (int) msg.getSrtpProtectionProfilesLength().getValue());

        assertArrayEquals(srtpMki, msg.getSrtpMki().getValue());
        assertEquals(srtpMkiLength, (int) msg.getSrtpMkiLength().getValue());
    }
}
