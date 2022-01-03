/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerNamePairSerializerTest {

    private ServerNamePairSerializer serializer;
    private ServerNamePair pair;

    @Before
    public void setUp() {
    }

    /**
     * Test of serializeBytes method, of class ServerNamePairSerializer.
     */
    @Test
    public void testSerializeBytes() {
        pair = new ServerNamePair((byte) 3, null);
        pair.setServerNameLength(123);
        pair.setServerNameType((byte) 3);
        pair.setServerName(new byte[] { 1, 2, 3, 4, });
        serializer = new ServerNamePairSerializer(pair);
        byte[] result = serializer.serialize();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03007B01020304"), result);
    }

}
