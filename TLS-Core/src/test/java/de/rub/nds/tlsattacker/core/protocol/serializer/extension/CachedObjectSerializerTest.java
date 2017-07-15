/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedObjectSerializerTest {

    private CachedObjectSerializer serializer;
    private CachedObject object;

    @Before
    public void setUp() {

    }

    @Test
    public void testSerializeBytes() {
        object = new CachedObject(false, (byte) 1, 0, new byte[] {});
        serializer = new CachedObjectSerializer(object);
        assertArrayEquals(new byte[] { (byte) 1 }, serializer.serialize());

        object = new CachedObject(true, (byte) 2, 3, new byte[] { 0x01, 0x02, 0x03 });
        serializer = new CachedObjectSerializer(object);
        assertArrayEquals(new byte[] { 0x02, 0x03, 0x01, 0x02, 0x03 }, serializer.serialize());
    }
}
