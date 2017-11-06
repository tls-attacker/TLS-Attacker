/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class KeySharePairSerializerTest {

    private KeySharePairSerializer serializer;
    private KeySharePair pair;

    public KeySharePairSerializerTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of serializeBytes method, of class KeySharePairSerializer.
     */
    @Test
    public void testSerializeBytes() {
        pair = new KeySharePair();
        pair.setKeyShareLength(32);
        pair.setKeyShareType(ArrayConverter.hexStringToByteArray("001D"));
        pair.setKeyShare(ArrayConverter
                .hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        serializer = new KeySharePairSerializer(pair);
        byte[] result = serializer.serialize();
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                result);
    }

}
