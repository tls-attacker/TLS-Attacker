/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.https.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class TokenBindingHeaderPreparatorTest {

    private TokenBindingHeader header;
    private TokenBindingHeaderPreparator preparator;

    @Before
    public void setUp() throws Exception {
        TlsContext context = new TlsContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        List<TokenBindingKeyParameters> keyParameters = new ArrayList<TokenBindingKeyParameters>();
        keyParameters.add(TokenBindingKeyParameters.ECDSAP256);
        context.getConfig().setDefaultTokenBindingKeyParameters(keyParameters);
        context.getConfig().setDefaultTokenBindingEcPrivateKey(BigInteger.valueOf(3));

        header = new TokenBindingHeader();
        preparator = new TokenBindingHeaderPreparator(context.getChooser(), header);
    }

    /**
     * Test of prepare method, of class TokenBindingHeaderPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();

        assertEquals(header.getHeaderName().getValue(), "Sec-Token-Binding");
        assertEquals(
                header.getHeaderValue().getValue(),
                "AIkAAgBBQF7L5NGmMwpEyPfvlR1L8WXmxrch762phftBZhvG5_1shzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDIAQBiMGdH7awDozrs8wPI2pfRAqtPX2vx3LTNCmY-9ngpdWHu9GFxflmo9jN0yKR1IxnVNtU-85XOUEwjlYaPYUJMAAA");
    }

}
