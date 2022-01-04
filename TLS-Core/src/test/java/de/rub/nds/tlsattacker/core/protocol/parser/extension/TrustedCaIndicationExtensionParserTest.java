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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedAuthorityPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class TrustedCaIndicationExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
            .asList(
                new Object[][] {
                    { ArrayConverter.hexStringToByteArray("0009000200050102030405"),
                        Arrays.asList(new TrustedAuthority((byte) 0, null, null, null),
                            new TrustedAuthority((byte) 2, null, 5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 })),
                        9 } });
    }

    private final byte[] extensionBytes;
    private final List<TrustedAuthority> trustedAuthoritiesList;
    private final int trustedAuthoritiesLength;

    public TrustedCaIndicationExtensionParserTest(byte[] extensionBytes, List<TrustedAuthority> trustedAuthoritiesList,
        int trustedAuthoritiesLength) {
        this.extensionBytes = extensionBytes;
        this.trustedAuthoritiesList = trustedAuthoritiesList;
        this.trustedAuthoritiesLength = trustedAuthoritiesLength;
    }

    @Before
    public void setUp() {
        for (TrustedAuthority ta : trustedAuthoritiesList) {
            TrustedAuthorityPreparator preparator = new TrustedAuthorityPreparator(new TlsContext().getChooser(), ta);
            preparator.prepare();
        }
    }

    @Test
    public void testParse() {
        TrustedCaIndicationExtensionParser parser =
            new TrustedCaIndicationExtensionParser(new ByteArrayInputStream(extensionBytes), Config.createConfig());
        TrustedCaIndicationExtensionMessage msg = new TrustedCaIndicationExtensionMessage();
        parser.parse(msg);
        assertEquals(trustedAuthoritiesLength, (long) msg.getTrustedAuthoritiesLength().getValue());
        assertCachedObjectList(trustedAuthoritiesList, msg.getTrustedAuthorities());
    }

    public void assertCachedObjectList(List<TrustedAuthority> expected, List<TrustedAuthority> actual) {
        for (int i = 0; i < expected.size(); i++) {
            TrustedAuthority expectedObject = expected.get(i);
            TrustedAuthority actualObject = actual.get(i);

            assertEquals(expectedObject.getIdentifierType().getValue(), actualObject.getIdentifierType().getValue());
            if (expectedObject.getDistinguishedNameLength() != null
                && expectedObject.getDistinguishedNameLength().getValue() != null) {
                assertEquals(expectedObject.getDistinguishedNameLength().getValue(),
                    actualObject.getDistinguishedNameLength().getValue());
            } else {
                assertNull(actualObject.getDistinguishedNameLength());
            }
            if (expectedObject.getSha1Hash() != null && expectedObject.getSha1Hash().getValue() != null) {
                assertArrayEquals(expectedObject.getSha1Hash().getValue(), actualObject.getSha1Hash().getValue());
            } else {
                assertNull(actualObject.getSha1Hash());
            }
            if (expectedObject.getDistinguishedName() != null
                && expectedObject.getDistinguishedName().getValue() != null) {
                assertArrayEquals(expectedObject.getDistinguishedName().getValue(),
                    actualObject.getDistinguishedName().getValue());
            } else {
                assertNull(actualObject.getDistinguishedName());
            }
        }
    }
}
