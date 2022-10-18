/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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
        byte[] algoBytes = ArrayConverter.concatenate(SignatureAndHashAlgorithm.DSA_SHA1.getByteValue(),
            SignatureAndHashAlgorithm.RSA_SHA512.getByteValue());
        msg.setSignatureAndHashAlgorithms(algoBytes);
        context.setServerSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA512);
        handler.adjustContext(msg);
        assertTrue(context.getClientSupportedSignatureAndHashAlgorithms().size() == 2);
        assertTrue(
            context.getClientSupportedSignatureAndHashAlgorithms().get(0).getHashAlgorithm() == HashAlgorithm.SHA1);
        assertTrue(context.getClientSupportedSignatureAndHashAlgorithms().get(0).getSignatureAlgorithm()
            == SignatureAlgorithm.DSA);
        assertEquals(SignatureAndHashAlgorithm.RSA_SHA512, context.getSelectedSignatureAndHashAlgorithm());
    }
}
