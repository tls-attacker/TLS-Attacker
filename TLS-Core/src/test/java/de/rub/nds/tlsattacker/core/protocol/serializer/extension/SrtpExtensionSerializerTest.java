/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SrtpExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SrtpExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SrtpExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int srtpProtectionProfilesLength;
    private final byte[] srtpProtectionProfiles;
    private final int srtpMkiLength;
    private final byte[] srtpMki;
    private SrtpExtensionSerializer serializer;
    private SrtpExtensionMessage msg;

    public SrtpExtensionSerializerTest(ExtensionType extensionType, byte[] expectedBytes, int extensionLength,
            int startParsing, int srtpProtectionProfilesLength, byte[] srtpProtectionProfiles, int srtpMkiLength,
            byte[] srtpMki) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.srtpProtectionProfilesLength = srtpProtectionProfilesLength;
        this.srtpProtectionProfiles = srtpProtectionProfiles;
        this.srtpMkiLength = srtpMkiLength;
        this.srtpMki = srtpMki;
    }

    @Before
    public void setUp() {
        msg = new SrtpExtensionMessage();
        serializer = new SrtpExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setExtensionType(extensionType.getValue());
        msg.setExtensionLength(extensionLength);

        msg.setSrtpProtectionProfilesLength(srtpProtectionProfilesLength);
        msg.setSrtpProtectionProfiles(srtpProtectionProfiles);
        msg.setSrtpMkiLength(srtpMkiLength);
        msg.setSrtpMki(srtpMki);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
