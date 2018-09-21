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
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class TrustedAuthorityParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { TrustedCaIndicationIdentifierType.PRE_AGREED, null, null, null, new byte[] { 0 } },
                { TrustedCaIndicationIdentifierType.KEY_SHA1_HASH,
                        ArrayConverter.hexStringToByteArray("da39a3ee5e6b4b0d3255bfef95601890afd80709"), null, null,
                        ArrayConverter.hexStringToByteArray("01da39a3ee5e6b4b0d3255bfef95601890afd80709") },
                { TrustedCaIndicationIdentifierType.X509_NAME, null, 5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 },
                        new byte[] { 0x02, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 } },
                { TrustedCaIndicationIdentifierType.CERT_SHA1_HASH,
                        ArrayConverter.hexStringToByteArray("da39a3ee5e6b4b0d3255bfef95601890afd80709"), null, null,
                        ArrayConverter.hexStringToByteArray("03da39a3ee5e6b4b0d3255bfef95601890afd80709") } });
    }

    private final TrustedCaIndicationIdentifierType identifier;
    private final byte[] hash;
    private final Integer distNameLength;
    private final byte[] distName;
    private final byte[] parserBytes;

    public TrustedAuthorityParserTest(TrustedCaIndicationIdentifierType identifier, byte[] hash,
            Integer distNameLength, byte[] distName, byte[] parserBytes) {
        this.identifier = identifier;
        this.hash = hash;
        this.distNameLength = distNameLength;
        this.distName = distName;
        this.parserBytes = parserBytes;
    }

    @Test
    public void parse() {

        TrustedAuthorityParser parser = new TrustedAuthorityParser(0, parserBytes);
        TrustedAuthority authority = parser.parse();

        assertEquals(identifier.getValue(), (long) authority.getIdentifierType().getValue());
        if (hash != null) {
            assertArrayEquals(hash, authority.getSha1Hash().getValue());
        } else {
            assertNull(authority.getSha1Hash());
        }
        if (distNameLength != null) {
            assertEquals(distNameLength, authority.getDistinguishedNameLength().getValue());
        } else {
            assertNull(authority.getDistinguishedNameLength());
        }
        if (distName != null) {
            assertArrayEquals(distName, authority.getDistinguishedName().getValue());
        } else {
            assertNull(authority.getDistinguishedName());
        }
    }

}
