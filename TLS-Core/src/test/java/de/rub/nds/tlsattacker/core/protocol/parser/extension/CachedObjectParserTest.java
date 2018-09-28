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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CachedObjectParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ConnectionEndType.SERVER, CachedInfoType.CERT, null, null, new byte[] { 0x01 } },
                { ConnectionEndType.SERVER, CachedInfoType.CERT_REQ, null, null, new byte[] { 0x02 } },
                { ConnectionEndType.CLIENT, CachedInfoType.CERT, 6, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
                        new byte[] { 0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } },
                { ConnectionEndType.CLIENT, CachedInfoType.CERT_REQ, 6,
                        new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
                        new byte[] { 0x02, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } } });
    }

    private final ConnectionEndType speakingEndType;
    private final CachedInfoType infoType;
    private final Integer hashLength;
    private final byte[] hash;
    private final byte[] cachedObjectBytes;

    public CachedObjectParserTest(ConnectionEndType speakingEndType, CachedInfoType infoType, Integer hashLength,
            byte[] hash, byte[] cachedObjectBytes) {
        this.speakingEndType = speakingEndType;
        this.infoType = infoType;
        this.hashLength = hashLength;
        this.hash = hash;
        this.cachedObjectBytes = cachedObjectBytes;
    }

    @Test
    public void parse() {
        CachedObjectParser parser = new CachedObjectParser(0, cachedObjectBytes, speakingEndType);
        CachedObject cachedObject = parser.parse();

        assertEquals(infoType.getValue(), (long) cachedObject.getCachedInformationType().getValue());

        if (hashLength != null) {
            assertEquals(hashLength, cachedObject.getHashValueLength().getValue());
        } else {
            assertNull(cachedObject.getHashValueLength());
        }
        if (hash != null) {
            assertArrayEquals(hash, cachedObject.getHashValue().getValue());
        } else {
            assertNull(cachedObject.getHashValue());
        }
    }

}
