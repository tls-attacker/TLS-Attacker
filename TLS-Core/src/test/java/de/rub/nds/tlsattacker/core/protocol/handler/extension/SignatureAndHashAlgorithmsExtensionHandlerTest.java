/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class SignatureAndHashAlgorithmsExtensionHandlerTest {

    private SignatureAndHashAlgorithmsExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SignatureAndHashAlgorithmsExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class SignatureAndHashAlgorithmsExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        SignatureAndHashAlgorithmsExtensionMessage msg = new SignatureAndHashAlgorithmsExtensionMessage();
        msg.setSignatureAndHashAlgorithms(new byte[] { 0, 0 });
        handler.adjustContext(msg);
        assertTrue(context.getClientSupportedSignatureAndHashAlgorithms().size() == 1);
        assertTrue(
            context.getClientSupportedSignatureAndHashAlgorithms().get(0).getHashAlgorithm() == HashAlgorithm.NONE);
        assertTrue(context.getClientSupportedSignatureAndHashAlgorithms().get(0).getSignatureAlgorithm()
            == SignatureAlgorithm.ANONYMOUS);
    }
}
