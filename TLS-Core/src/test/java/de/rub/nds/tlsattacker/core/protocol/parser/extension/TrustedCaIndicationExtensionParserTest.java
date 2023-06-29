/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedAuthorityPreparator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class TrustedCaIndicationExtensionParserTest
        extends AbstractExtensionParserTest<
                TrustedCaIndicationExtensionMessage, TrustedCaIndicationExtensionParser> {

    public TrustedCaIndicationExtensionParserTest() {
        super(
                TrustedCaIndicationExtensionMessage.class,
                TrustedCaIndicationExtensionParser::new,
                List.of(
                        Named.of(
                                "TrustedCaIndicationExtensionMessage::getTrustedAuthoritiesLength",
                                TrustedCaIndicationExtensionMessage::getTrustedAuthoritiesLength)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0003000B0009000200050102030405"),
                        List.of(),
                        ExtensionType.TRUSTED_CA_KEYS,
                        11,
                        List.of(
                                9,
                                List.of(
                                        new TrustedAuthority((byte) 0, null, null, null),
                                        new TrustedAuthority(
                                                (byte) 2,
                                                null,
                                                5,
                                                new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})))));
    }

    @Override
    protected void assertExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> expectedMessageSpecificValues) {
        // noinspection unchecked
        for (TrustedAuthority ta : (List<TrustedAuthority>) expectedMessageSpecificValues.get(1)) {
            TrustedAuthorityPreparator preparator =
                    new TrustedAuthorityPreparator(new TlsContext().getChooser(), ta);
            preparator.prepare();
        }

        super.assertExtensionMessageSpecific(
                providedAdditionalValues, expectedMessageSpecificValues);
        // noinspection unchecked
        assertCachedObjectList(
                (List<TrustedAuthority>) expectedMessageSpecificValues.get(1),
                message.getTrustedAuthorities());
    }

    private void assertCachedObjectList(
            List<TrustedAuthority> expected, List<TrustedAuthority> actual) {
        for (int i = 0; i < expected.size(); i++) {
            TrustedAuthority expectedObject = expected.get(i);
            TrustedAuthority actualObject = actual.get(i);

            assertEquals(
                    expectedObject.getIdentifierType().getValue(),
                    actualObject.getIdentifierType().getValue());
            if (expectedObject.getDistinguishedNameLength() != null
                    && expectedObject.getDistinguishedNameLength().getValue() != null) {
                assertEquals(
                        expectedObject.getDistinguishedNameLength().getValue(),
                        actualObject.getDistinguishedNameLength().getValue());
            } else {
                assertNull(actualObject.getDistinguishedNameLength());
            }
            if (expectedObject.getSha1Hash() != null
                    && expectedObject.getSha1Hash().getValue() != null) {
                assertArrayEquals(
                        expectedObject.getSha1Hash().getValue(),
                        actualObject.getSha1Hash().getValue());
            } else {
                assertNull(actualObject.getSha1Hash());
            }
            if (expectedObject.getDistinguishedName() != null
                    && expectedObject.getDistinguishedName().getValue() != null) {
                assertArrayEquals(
                        expectedObject.getDistinguishedName().getValue(),
                        actualObject.getDistinguishedName().getValue());
            } else {
                assertNull(actualObject.getDistinguishedName());
            }
        }
    }
}
