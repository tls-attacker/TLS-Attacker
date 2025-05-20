/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CertificateRequestPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                CertificateRequestMessage, CertificateRequestPreparator> {

    public CertificateRequestPreparatorTest() {
        super(
                CertificateRequestMessage::new,
                CertificateRequestMessage::new,
                CertificateRequestPreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class CertificateRequestPreparator. */
    @Test
    @Override
    public void testPrepare() {
        tlsContext.getConfig().setDistinguishedNames(new byte[] {0, 1, 2});
        List<ClientCertificateType> list = new LinkedList<>();
        list.add(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED);
        list.add(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED);
        tlsContext.getConfig().setClientCertificateTypes(list);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        tlsContext.getConfig().setDefaultServerSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        assertArrayEquals(new byte[] {0, 1, 2}, message.getDistinguishedNames().getValue());
        assertEquals(3, (int) message.getDistinguishedNamesLength().getValue());
        assertArrayEquals(new byte[] {6, 5}, message.getClientCertificateTypes().getValue());
        assertArrayEquals(new byte[] {2, 0, 6, 3}, message.getSignatureHashAlgorithms().getValue());
        assertEquals(4, (int) message.getSignatureHashAlgorithmsLength().getValue());
    }

    /** Test of prepareHandshakeMessageContents method, of class CertificateRequestPreparator. */
    @Test
    public void testPrepareTls13() {
        tlsContext.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        createNewMessageAndPreparator(true);
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        tlsContext.getConfig().setDefaultServerSupportedSignatureAndHashAlgorithms(algoList);
        tlsContext.getConfig().setDefaultCertificateRequestContext(new byte[] {0, 1, 2});
        preparator.prepare();
        assertArrayEquals(new byte[] {0, 1, 2}, message.getCertificateRequestContext().getValue());
        assertEquals(3, (int) message.getCertificateRequestContextLength().getValue());
        assertNotNull(message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class));
        assertArrayEquals(
                new byte[] {2, 0, 6, 3},
                message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class)
                        .getSignatureAndHashAlgorithms()
                        .getValue());
    }

    @Test
    public void testPrepareTls13WithoutSettingDefaultCertificateRequestContext() {
        tlsContext.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        createNewMessageAndPreparator(true);
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        tlsContext.getConfig().setDefaultServerSupportedSignatureAndHashAlgorithms(algoList);

        // Explicitly skip setDefaultCertificateRequestContext

        assertDoesNotThrow(() -> preparator.prepare());
        assertArrayEquals(new byte[0], message.getCertificateRequestContext().getValue());
        assertEquals(0, (int) message.getCertificateRequestContextLength().getValue());
        assertNotNull(message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class));
        assertArrayEquals(
                new byte[] {2, 0, 6, 3},
                message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class)
                        .getSignatureAndHashAlgorithms()
                        .getValue());
    }

    @Test
    public void testPrepareTls13WithNullDefaultCertificateRequestContext() {
        tlsContext.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        createNewMessageAndPreparator(true);
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        tlsContext.getConfig().setDefaultServerSupportedSignatureAndHashAlgorithms(algoList);

        // Try to set DefaultCertificateRequestContext to null
        assertThrows(
                IllegalArgumentException.class,
                () -> tlsContext.getConfig().setDefaultCertificateRequestContext(null));
    }
}
