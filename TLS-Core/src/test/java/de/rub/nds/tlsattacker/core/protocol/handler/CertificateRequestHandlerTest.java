/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CertificateRequestHandlerTest {

    private CertificateRequestHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateRequestHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class CertificateRequestHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof CertificateRequestParser);
    }

    /**
     * Test of getPreparator method, of class CertificateRequestHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateRequestMessage()) instanceof CertificateRequestPreparator);
    }

    /**
     * Test of getSerializer method, of class CertificateRequestHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateRequestMessage()) instanceof CertificateRequestSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class CertificateRequestHandler.
     */
    @Test
    public void testAdjustTLSContextTLS12() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setClientCertificateTypes(new byte[] { 1, 2, 3, 4, 5, 6 });
        message.setDistinguishedNames(new byte[] { 0, 1, 2, 3, });
        message.setSignatureHashAlgorithms(new byte[] { 03, 01, 01, 03 });
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getDistinguishedNames(), ArrayConverter.hexStringToByteArray("00010203"));
        assertTrue(context.getClientCertificateTypes().size() == 6);
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.DSS_FIXED_DH));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.DSS_SIGN));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.RSA_FIXED_DH));
        assertTrue(context.getClientCertificateTypes().contains(ClientCertificateType.RSA_SIGN));
        assertTrue(context.getServerSupportedSignatureAndHashAlgorithms().size() == 2);
    }

    /**
     * Test of adjustTLSContext method, of class CertificateRequestHandler.
     */
    @Test
    public void testAdjustTLSContextTLS13() {
        Config config = Config.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);

        CertificateRequestMessage message = new CertificateRequestMessage(config);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        message.setCertificateRequestContext(new byte[] { 1, 2, 3, 4, 5, 6 });
        message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class)
            .setSignatureAndHashAlgorithms(new byte[] { 03, 01, 01, 03 });
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getCertificateRequestContext(), ArrayConverter.hexStringToByteArray("010203040506"));
        assertTrue(context.getServerSupportedSignatureAndHashAlgorithms().size() == 2);
    }

    @Test
    public void testAdjustTLSContextUnadjustable() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setClientCertificateTypes(new byte[] { 50, 51, 52, 53, 54, 55 });
        message.setDistinguishedNames(new byte[] {});
        message.setSignatureHashAlgorithms(new byte[] { 123, 123, 127 });
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getDistinguishedNames(), new byte[0]);
        assertTrue(context.getClientCertificateTypes().isEmpty());
        assertTrue(context.getServerSupportedSignatureAndHashAlgorithms().isEmpty());
    }
}
