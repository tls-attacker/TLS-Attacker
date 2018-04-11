/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class CertificateMessageHandlerTest {

    private CertificateMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = new TlsContext();
        handler = new CertificateMessageHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class CertificateMessageHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof CertificateMessageParser);
    }

    /**
     * Test of getPreparator method, of class CertificateMessageHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateMessage()) instanceof CertificateMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class CertificateMessageHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateMessage()) instanceof CertificateMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class CertificateMessageHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        for (ProtocolVersion version : new ProtocolVersion[] { ProtocolVersion.TLS12 }) {
            context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
            context.setSelectedProtocolVersion(version);
            CertificateMessage message = new CertificateMessage();
            message.setCertificatesListBytes(ArrayConverter
                    .hexStringToByteArray("00023a30820236308201dba0030201020209008812dc4bf7943e2b300a06082a8648ce3d0403023077310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d312f302d060355040a0c263c7363726970743e616c6572742827544c532d41747461636b657227293c2f7363726970743e3118301606035504030c0f746c732d61747461636b65722e6465301e170d3137303232323132353032385a170d3138303232323132353032385a3077310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d312f302d060355040a0c263c7363726970743e616c6572742827544c532d41747461636b657227293c2f7363726970743e3118301606035504030c0f746c732d61747461636b65722e64653059301306072a8648ce3d020106082a8648ce3d03010703420004fbca33b6018a6b244aea13a5332b505daa865026a565f7c7dc3aed6d8b8193248abb4000cf4a1c2c29d94ce1072454ea0a990cd97c863b931f266cc3addad922a350304e301d0603551d0e041604141e9b408ab6236764f8a1d26ed696f009d7b18904301f0603551d230418301680141e9b408ab6236764f8a1d26ed696f009d7b18904300c0603551d13040530030101ff300a06082a8648ce3d0403020349003046022100c9c06d798bbdf6809a3c9523bb979a64a0565fb1759182d6f6bcf6849cd70c7d022100b8e695c1915f71a348600ca90d48dfead7ea5c97b116b05c270af595c94bfa8d"));
            message.setCertificatesListLength(573);
            handler.adjustTLSContext(message);
            assertNotNull(context.getClientCertificate());
            assertNull(context.getServerCertificate());
            context = new TlsContext();
            context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
            context.setSelectedProtocolVersion(version);
            handler = new CertificateMessageHandler(context);
            handler.adjustTLSContext(message);
            assertNull(context.getClientCertificate());
            assertNotNull(context.getServerCertificate());
        }
    }

    @Test
    public void testAdjustTLSContextWithUnparsableCertificate() {
        for (ProtocolVersion version : new ProtocolVersion[] { ProtocolVersion.SSL3, ProtocolVersion.TLS10,
                ProtocolVersion.TLS11, ProtocolVersion.TLS12 }) {
            context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
            context.setSelectedProtocolVersion(version);
            CertificateMessage message = new CertificateMessage();
            message.setCertificatesListBytes(new byte[] { 0, 1, 2, 3, 4 });
            message.setCertificatesListLength(5);
            handler.adjustTLSContext(message);
            assertNull(context.getClientCertificate());
            assertNull(context.getServerCertificate());
            context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
            context.setSelectedProtocolVersion(version);
            message.setCertificatesListBytes(new byte[] { 0, 1, 2, 3, 4 });
            handler.adjustTLSContext(message);
            assertNull(context.getClientCertificate());
            assertNull(context.getServerCertificate());
        }
    }
}
