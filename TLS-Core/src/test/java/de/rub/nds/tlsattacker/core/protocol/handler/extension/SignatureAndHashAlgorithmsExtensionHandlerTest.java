/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import org.junit.jupiter.api.Test;

public class SignatureAndHashAlgorithmsExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                SignatureAndHashAlgorithmsExtensionMessage,
                SignatureAndHashAlgorithmsExtensionHandler> {

    public SignatureAndHashAlgorithmsExtensionHandlerTest() {
        super(
                SignatureAndHashAlgorithmsExtensionMessage::new,
                SignatureAndHashAlgorithmsExtensionHandler::new);
    }

    /** Test of adjustContext method, of class SignatureAndHashAlgorithmsExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        SignatureAndHashAlgorithmsExtensionMessage msg =
                new SignatureAndHashAlgorithmsExtensionMessage();
        byte[] algoBytes =
                ArrayConverter.concatenate(
                        SignatureAndHashAlgorithm.DSA_SHA1.getByteValue(),
                        SignatureAndHashAlgorithm.RSA_SHA512.getByteValue());
        msg.setSignatureAndHashAlgorithms(algoBytes);
        context.setServerSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA512);
        handler.adjustTLSExtensionContext(msg);
        assertEquals(2, context.getClientSupportedSignatureAndHashAlgorithms().size());
        assertSame(
                HashAlgorithm.SHA1,
                context.getClientSupportedSignatureAndHashAlgorithms().get(0).getHashAlgorithm());
        assertSame(
                SignatureAlgorithm.DSA,
                context.getClientSupportedSignatureAndHashAlgorithms()
                        .get(0)
                        .getSignatureAlgorithm());
        assertEquals(
                SignatureAndHashAlgorithm.RSA_SHA512,
                context.getSelectedSignatureAndHashAlgorithm());
    }
}
