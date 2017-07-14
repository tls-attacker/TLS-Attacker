/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.CachedInfoType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class CachedObjectParserTest {

    private final boolean isClientState;
    private final CachedInfoType infoType;
    private final int hashLength;
    private final byte[] hash;
    private final byte[] cachedObjectBytes;

    public CachedObjectParserTest(boolean isClientState, CachedInfoType infoType, int hashLength, byte[] hash,
            byte[] cachedObjectBytes) {
        this.isClientState = isClientState;
        this.infoType = infoType;
        this.hashLength = hashLength;
        this.hash = hash;
        this.cachedObjectBytes = cachedObjectBytes;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { false, CachedInfoType.CERT, 0, new byte[] {}, new byte[] { 0x01 } },
                { false, CachedInfoType.CERT_REQ, 0, new byte[] {}, new byte[] { 0x02 } },
                { true, CachedInfoType.CERT, 6, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
                        new byte[] { 0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } },
                { true, CachedInfoType.CERT_REQ, 6, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
                        new byte[] { 0x02, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } } });
    }

    @Test
    public void parse() {
        CachedObjectParser parser = new CachedObjectParser(0, cachedObjectBytes, isClientState);
        CachedObject cachedObject = parser.parse();

        assertEquals(isClientState, cachedObject.getIsClientState().getValue());
        assertEquals(infoType.getValue(), (byte) cachedObject.getCachedInformationType().getValue());
        assertEquals(hashLength, (int) cachedObject.getHashValueLength().getValue());
        assertArrayEquals(hash, cachedObject.getHashValue().getValue());
    }

}
