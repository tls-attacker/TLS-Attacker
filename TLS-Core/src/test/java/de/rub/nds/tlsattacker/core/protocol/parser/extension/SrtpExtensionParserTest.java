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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
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
public class SrtpExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("000400010006020102"), 4,
                ArrayConverter.hexStringToByteArray("00010006"), 2, new byte[] { 0x01, 0x02 } },
            { ArrayConverter.hexStringToByteArray("00040001000600"), 4, ArrayConverter.hexStringToByteArray("00010006"),
                0, new byte[0] } });
    }

    private final byte[] expectedBytes;
    private final int srtpProtectionProfilesLength;
    private final byte[] srtpProtectionProfiles;
    private final int srtpMkiLength;
    private final byte[] srtpMki;
    private SrtpExtensionParser parser;

    public SrtpExtensionParserTest(byte[] expectedBytes, int srtpProtectionProfilesLength,
        byte[] srtpProtectionProfiles, int srtpMkiLength, byte[] srtpMki) {
        this.expectedBytes = expectedBytes;
        this.srtpProtectionProfilesLength = srtpProtectionProfilesLength;
        this.srtpProtectionProfiles = srtpProtectionProfiles;
        this.srtpMkiLength = srtpMkiLength;
        this.srtpMki = srtpMki;
    }

    @Before
    public void setUp() {
        parser = new SrtpExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
    }

    @Test
    public void testParse() {
        SrtpExtensionMessage msg = new SrtpExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(srtpProtectionProfiles, msg.getSrtpProtectionProfiles().getValue());
        assertEquals(srtpProtectionProfilesLength, (long) msg.getSrtpProtectionProfilesLength().getValue());
        assertEquals(srtpMkiLength, (long) msg.getSrtpMkiLength().getValue());
        assertArrayEquals(srtpMki, msg.getSrtpMki().getValue());
    }
}
