/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedAuthorityPreparator;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class TrustedCaIndicationExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                TrustedCaIndicationExtensionMessage, TrustedCaIndicationExtensionHandler> {

    private final List<TrustedAuthority> trustedAuthorities =
            Arrays.asList(
                    new TrustedAuthority((byte) 0, new byte[] {}, 0, new byte[] {}),
                    new TrustedAuthority(
                            (byte) 2, new byte[] {}, 5, new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}));

    public TrustedCaIndicationExtensionHandlerTest() {
        super(TrustedCaIndicationExtensionMessage::new, TrustedCaIndicationExtensionHandler::new);
        for (TrustedAuthority ta : trustedAuthorities) {
            TrustedAuthorityPreparator preparator =
                    new TrustedAuthorityPreparator(context.getChooser(), ta);
            preparator.prepare();
        }
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        TrustedCaIndicationExtensionMessage msg = new TrustedCaIndicationExtensionMessage();
        msg.setTrustedAuthorities(trustedAuthorities);
        handler.adjustTLSExtensionContext(msg);
        assertTrustedAuthorityList(
                trustedAuthorities, context.getTrustedCaIndicationExtensionCas());
    }

    public void assertTrustedAuthorityList(
            List<TrustedAuthority> expected, List<TrustedAuthority> actual) {
        for (int i = 0; i < expected.size(); i++) {
            TrustedAuthority expectedObject = expected.get(i);
            TrustedAuthority actualObject = actual.get(i);

            assertEquals(
                    expectedObject.getIdentifierType().getValue(),
                    actualObject.getIdentifierType().getValue());
            assertEquals(
                    expectedObject.getDistinguishedNameLength().getValue(),
                    actualObject.getDistinguishedNameLength().getValue());
            assertArrayEquals(
                    expectedObject.getSha1Hash().getValue(), actualObject.getSha1Hash().getValue());
            assertArrayEquals(
                    expectedObject.getDistinguishedName().getValue(),
                    actualObject.getDistinguishedName().getValue());
        }
    }
}
