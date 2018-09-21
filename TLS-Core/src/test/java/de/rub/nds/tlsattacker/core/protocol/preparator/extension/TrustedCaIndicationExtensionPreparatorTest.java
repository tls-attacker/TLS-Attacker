/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class TrustedCaIndicationExtensionPreparatorTest {

    private TlsContext context;
    private TrustedCaIndicationExtensionMessage msg;
    private TrustedCaIndicationExtensionPreparator preparator;
    private final int authoritiesLength = 8;
    private final List<TrustedAuthority> trustedAuthorities = Arrays.asList(new TrustedAuthority((byte) 0,
            new byte[] {}, 0, new byte[] {}), new TrustedAuthority((byte) 2, new byte[] {}, 5, new byte[] { 0x01, 0x02,
            0x03, 0x04, 0x05 }));

    @Test
    public void testPreparator() {
        context = new TlsContext();
        msg = new TrustedCaIndicationExtensionMessage();
        preparator = new TrustedCaIndicationExtensionPreparator(context.getChooser(), msg,
                new TrustedCaIndicationExtensionSerializer(msg));

        context.getConfig().setTrustedCaIndicationExtensionAuthorties(trustedAuthorities);

        preparator.prepare();

        assertEquals(authoritiesLength, (long) msg.getTrustedAuthoritiesLength().getValue());
        assertTrustedAuthorityList(trustedAuthorities, msg.getTrustedAuthorities());
    }

    public void assertTrustedAuthorityList(List<TrustedAuthority> expected, List<TrustedAuthority> actual) {
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
