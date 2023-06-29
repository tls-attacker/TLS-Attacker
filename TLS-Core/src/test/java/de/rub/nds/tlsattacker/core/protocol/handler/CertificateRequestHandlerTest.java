/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import java.util.Objects;
import org.junit.jupiter.api.Test;

public class CertificateRequestHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                CertificateRequestMessage, CertificateRequestHandler> {

    public CertificateRequestHandlerTest() {
        super(CertificateRequestMessage::new, CertificateRequestHandler::new);
    }

    /** Test of adjustContext method, of class CertificateRequestHandler. */
    @Test
    @Override
    public void testadjustContext() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setClientCertificateTypes(new byte[] {1, 2, 3, 4, 5, 6});
        message.setDistinguishedNames(
                new byte[] {
                    0, 1, 2, 3,
                });
        message.setSignatureHashAlgorithms(new byte[] {0x03, 0x01, 0x01, 0x03});
        handler.adjustContext(message);
        assertArrayEquals(
                context.getDistinguishedNames(), ArrayConverter.hexStringToByteArray("00010203"));
        assertEquals(6, context.getClientCertificateTypes().size());
        assertTrue(
                context.getClientCertificateTypes()
                        .contains(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED));
        assertTrue(
                context.getClientCertificateTypes().contains(ClientCertificateType.DSS_FIXED_DH));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.DSS_SIGN));
        assertTrue(
                context.getClientCertificateTypes()
                        .contains(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED));
        assertTrue(
                context.getClientCertificateTypes().contains(ClientCertificateType.RSA_FIXED_DH));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.RSA_SIGN));
        assertEquals(2, context.getServerSupportedSignatureAndHashAlgorithms().size());
    }

    /** Test of adjustContext method, of class CertificateRequestHandler. */
    @Test
    public void testadjustContextTLS13() {
        Config config = Config.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);

        CertificateRequestMessage message = new CertificateRequestMessage(config);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        message.setCertificateRequestContext(new byte[] {1, 2, 3, 4, 5, 6});
        Objects.requireNonNull(
                        message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class))
                .setSignatureAndHashAlgorithms(new byte[] {0x03, 0x01, 0x01, 0x03});
        handler.adjustContext(message);
        assertArrayEquals(
                context.getCertificateRequestContext(),
                ArrayConverter.hexStringToByteArray("010203040506"));
        assertEquals(2, context.getServerSupportedSignatureAndHashAlgorithms().size());
    }

    @Test
    public void testadjustContextUnadjustable() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setClientCertificateTypes(new byte[] {50, 51, 52, 53, 54, 55});
        message.setDistinguishedNames(new byte[] {});
        message.setSignatureHashAlgorithms(new byte[] {123, 123, 127});
        handler.adjustContext(message);
        assertArrayEquals(context.getDistinguishedNames(), new byte[0]);
        assertTrue(context.getClientCertificateTypes().isEmpty());
        assertTrue(context.getServerSupportedSignatureAndHashAlgorithms().isEmpty());
    }
}
