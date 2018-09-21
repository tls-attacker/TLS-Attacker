/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedAuthorityParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedAuthorityPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class TrustedAuthoritySerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return TrustedAuthorityParserTest.generateData();
    }

    private final TrustedCaIndicationIdentifierType identifier;
    private final byte[] hash;
    private final Integer distNameLength;
    private final byte[] distName;
    private final byte[] parserBytes;
    private TrustedAuthoritySerializer serializer;
    private TrustedAuthority authority;

    public TrustedAuthoritySerializerTest(TrustedCaIndicationIdentifierType identifier, byte[] hash,
            Integer distNameLength, byte[] distName, byte[] parserBytes) {
        this.identifier = identifier;
        this.hash = hash;
        this.distNameLength = distNameLength;
        this.distName = distName;
        this.parserBytes = parserBytes;
    }

    @Test
    public void testSerializeBytes() {
        authority = new TrustedAuthority(identifier.getValue(), hash, distNameLength, distName);
        TrustedAuthorityPreparator preparator = new TrustedAuthorityPreparator(new TlsContext().getChooser(), authority);
        preparator.prepare();
        serializer = new TrustedAuthoritySerializer(authority);

        assertArrayEquals(parserBytes, serializer.serialize());
    }
}
