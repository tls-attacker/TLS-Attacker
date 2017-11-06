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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
@RunWith(Parameterized.class)
public class KeySharePairParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        ArrayConverter
                                .hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        32, ArrayConverter.hexStringToByteArray("001D") } });
    }

    private byte[] keySharePairBytes;
    private byte[] keyShare;
    private int keyShareLength;
    private byte[] keyShareType;

    public KeySharePairParserTest(byte[] keySharePairBytes, byte[] keyShare, int keyShareLength, byte[] keyShareType) {
        this.keySharePairBytes = keySharePairBytes;
        this.keyShare = keyShare;
        this.keyShareLength = keyShareLength;
        this.keyShareType = keyShareType;
    }

    /**
     * Test of parse method, of class KeySharePairParser.
     */
    @Test
    public void testParse() {
        KeySharePairParser parser = new KeySharePairParser(0, keySharePairBytes);
        KeySharePair pair = parser.parse();
        assertArrayEquals(keyShare, pair.getKeyShare().getValue());
        assertTrue(keyShareLength == pair.getKeyShareLength().getValue());
        assertArrayEquals(keyShareType, pair.getKeyShareType().getValue());
    }

}
