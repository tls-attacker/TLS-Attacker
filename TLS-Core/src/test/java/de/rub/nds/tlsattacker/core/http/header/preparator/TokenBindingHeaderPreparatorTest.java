/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http.header.preparator;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.http.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class TokenBindingHeaderPreparatorTest {

    private TokenBindingHeader header;
    private TokenBindingHeaderPreparator preparator;

    @Before
    public void setUp() throws Exception {
        HttpContext context = new HttpContext();

        List<TokenBindingKeyParameters> keyParameters = new ArrayList<TokenBindingKeyParameters>();
        keyParameters.add(TokenBindingKeyParameters.ECDSAP256);
        context.getConfig().setDefaultTokenBindingKeyParameters(keyParameters);
        context.getConfig().setDefaultTokenBindingEcPrivateKey(BigInteger.valueOf(3));

        header = new TokenBindingHeader();
        preparator = new TokenBindingHeaderPreparator(context, header);
    }

    /**
     * Test of prepare method, of class TokenBindingHeaderPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();

        assertEquals(header.getHeaderName().getValue(), "Sec-Token-Binding");
        assertEquals(header.getHeaderValue().getValue(),
            "AIkAAgBBQF7L5NGmMwpEyPfvlR1L8WXmxrch762phftBZhvG5_1shzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDIAQBiMGdH7awDozrs8wPI2pfRAqtPX2vx3LTNCmY-9ngpdWHu9GFxflmo9jN0yKR1IxnVNtU-85XOUEwjlYaPYUJMAAA");
    }

}
