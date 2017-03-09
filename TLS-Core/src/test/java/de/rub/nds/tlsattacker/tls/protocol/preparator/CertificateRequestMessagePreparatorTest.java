/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.LinkedList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessagePreparatorTest {

    private CertificateRequestMessagePreparator preparator;
    private CertificateRequestMessage message;
    private TlsContext context;

    public CertificateRequestMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new CertificateRequestMessage();
        preparator = new CertificateRequestMessagePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * CertificateRequestMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setDistinguishedNames(new byte[] { 0, 1, 2 });
        List<ClientCertificateType> list = new LinkedList<>();
        list.add(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED);
        list.add(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED);
        context.getConfig().setClientCertificateTypes(list);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ANONYMOUS, HashAlgorithm.SHA1));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512));
        context.getConfig().setSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        assertArrayEquals(new byte[] { 0, 1, 2 }, message.getDistinguishedNames().getValue());
        assertTrue(3 == message.getDistinguishedNamesLength().getValue());
        assertArrayEquals(new byte[] { 6, 5 }, message.getClientCertificateTypes().getValue());
        assertArrayEquals(new byte[] { 2, 0, 6, 3 }, message.getSignatureHashAlgorithms().getValue());
        assertTrue(4 == message.getSignatureHashAlgorithmsLength().getValue());
    }

}
