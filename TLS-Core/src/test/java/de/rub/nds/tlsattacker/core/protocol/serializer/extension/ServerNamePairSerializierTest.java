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
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerNamePairSerializierTest {

    private ServerNamePairSerializier serializer;
    private ServerNamePair pair;

    @Before
    public void setUp() {
    }

    /**
     * Test of serializeBytes method, of class ServerNamePairSerializier.
     */
    @Test
    public void testSerializeBytes() {
        pair = new ServerNamePair();
        pair.setServerNameLength(123);
        pair.setServerNameType((byte) 3);
        pair.setServerName(new byte[] { 1, 2, 3, 4, });
        serializer = new ServerNamePairSerializier(pair);
        byte[] result = serializer.serialize();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03007B01020304"), result);
    }

}
