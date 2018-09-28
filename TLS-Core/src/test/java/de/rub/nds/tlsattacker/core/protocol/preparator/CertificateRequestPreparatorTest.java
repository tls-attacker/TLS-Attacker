/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CertificateRequestPreparatorTest {

    private CertificateRequestPreparator preparator;
    private CertificateRequestMessage message;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new CertificateRequestMessage();
        preparator = new CertificateRequestPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * CertificateRequestPreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setDistinguishedNames(new byte[] { 0, 1, 2 });
        List<ClientCertificateType> list = new LinkedList<>();
        list.add(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED);
        list.add(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED);
        context.getConfig().setClientCertificateTypes(list);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        context.getConfig().setDefaultServerSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        assertArrayEquals(new byte[] { 0, 1, 2 }, message.getDistinguishedNames().getValue());
        assertTrue(3 == message.getDistinguishedNamesLength().getValue());
        assertArrayEquals(new byte[] { 6, 5 }, message.getClientCertificateTypes().getValue());
        assertArrayEquals(new byte[] { 2, 0, 6, 3 }, message.getSignatureHashAlgorithms().getValue());
        assertTrue(4 == message.getSignatureHashAlgorithmsLength().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
