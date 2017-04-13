/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNamePairSerializierTest {

    private ServerNamePairSerializier serializer;
    private ServerNamePair pair;

    public ServerNamePairSerializierTest() {
    }

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
