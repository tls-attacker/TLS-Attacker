/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.Test;

public class RSAServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                RSAServerKeyExchangeMessage, RSAServerKeyExchangeHandler> {

    public RSAServerKeyExchangeHandlerTest() {
        super(RSAServerKeyExchangeMessage::new, RSAServerKeyExchangeHandler::new);
    }

    @Test
    @Override
    public void testadjustContext() {
        RSAServerKeyExchangeMessage message = new RSAServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] {1, 2, 3});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        message.prepareKeyExchangeComputations();
        message.getKeyExchangeComputations().setPrivateKey(BigInteger.ZERO);
        tlsContext.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA1);
        message.setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA1.getByteValue());
        handler.adjustContext(message);

        assertEquals(BigInteger.TEN, tlsContext.getServerEphemeralRsaExportModulus());
        assertArrayEquals(
                new byte[] {1, 2, 3},
                tlsContext.getServerEphemeralRsaExportPublicKey().toByteArray());
        assertEquals(BigInteger.ZERO, tlsContext.getServerEphemeralRsaExportPrivateKey());
        assertEquals(
                SignatureAndHashAlgorithm.RSA_SHA1,
                tlsContext.getSelectedSignatureAndHashAlgorithm());
    }

    @Test
    public void testadjustContextWithoutComputations() {
        RSAServerKeyExchangeMessage message = new RSAServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] {1, 2, 3});
        tlsContext.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA1);
        message.setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA1.getByteValue());
        handler.adjustContext(message);

        assertEquals(BigInteger.TEN, tlsContext.getServerEphemeralRsaExportModulus());
        assertArrayEquals(
                new byte[] {1, 2, 3},
                tlsContext.getServerEphemeralRsaExportPublicKey().toByteArray());
        assertNull(tlsContext.getServerEphemeralRsaExportPrivateKey());
        assertEquals(
                SignatureAndHashAlgorithm.RSA_SHA1,
                tlsContext.getSelectedSignatureAndHashAlgorithm());
    }
}
