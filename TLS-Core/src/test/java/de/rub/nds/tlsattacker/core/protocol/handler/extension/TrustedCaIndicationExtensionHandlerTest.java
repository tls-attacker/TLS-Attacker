/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedCaIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedAuthorityPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedCaIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TrustedCaIndicationExtensionHandlerTest {

    private final List<TrustedAuthority> trustedAuthorities = Arrays.asList(new TrustedAuthority((byte) 0,
            new byte[] {}, 0, new byte[] {}), new TrustedAuthority((byte) 2, new byte[] {}, 5, new byte[] { 0x01, 0x02,
            0x03, 0x04, 0x05 }));
    private TrustedCaIndicationExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new TrustedCaIndicationExtensionHandler(context);
        for (TrustedAuthority ta : trustedAuthorities) {
            TrustedAuthorityPreparator preparator = new TrustedAuthorityPreparator(context.getChooser(), ta);
            preparator.prepare();
        }
    }

    @Test
    public void testAdjustTLSContext() {
        TrustedCaIndicationExtensionMessage msg = new TrustedCaIndicationExtensionMessage();

        msg.setTrustedAuthorities(trustedAuthorities);

        handler.adjustTLSContext(msg);

        assertTrustedAuthoritiyList(trustedAuthorities, context.getTrustedCaIndicationExtensionCas());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof TrustedCaIndicationExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new TrustedCaIndicationExtensionMessage()) instanceof TrustedCaIndicationExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new TrustedCaIndicationExtensionMessage()) instanceof TrustedCaIndicationExtensionSerializer);
    }

    public void assertTrustedAuthoritiyList(List<TrustedAuthority> expected, List<TrustedAuthority> actual) {
        for (int i = 0; i < expected.size(); i++) {
            TrustedAuthority expectedObject = expected.get(i);
            TrustedAuthority actualObject = actual.get(i);

            assertEquals(expectedObject.getIdentifierType().getValue(), actualObject.getIdentifierType().getValue());
            assertEquals(expectedObject.getDistinguishedNameLength().getValue(), actualObject
                    .getDistinguishedNameLength().getValue());
            assertArrayEquals(expectedObject.getSha1Hash().getValue(), actualObject.getSha1Hash().getValue());
            assertArrayEquals(expectedObject.getDistinguishedName().getValue(), actualObject.getDistinguishedName()
                    .getValue());
        }
    }

}
