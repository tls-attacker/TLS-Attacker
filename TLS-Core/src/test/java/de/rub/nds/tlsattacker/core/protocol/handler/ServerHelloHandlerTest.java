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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerHelloHandlerTest {

    private ServerHelloHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerHelloHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getPreparator method, of class ServerHelloHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ServerHelloMessage()) instanceof ServerHelloPreparator);
    }

    /**
     * Test of getSerializer method, of class ServerHelloHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ServerHelloMessage()) instanceof ServerHelloSerializer);
    }

    /**
     * Test of getParser method, of class ServerHelloHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ServerHelloParser);
    }

    /**
     * Test of adjustTLSContext method, of class ServerHelloHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 0, 1, 2, 3, 4, 5 });
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getServerRandom(), new byte[] { 0, 1, 2, 3, 4, 5 });
        assertTrue(context.getSelectedCompressionMethod() == CompressionMethod.DEFLATE);
        assertArrayEquals(context.getServerSessionId(), new byte[] { 6, 6, 6 });
        assertArrayEquals(context.getSelectedCipherSuite().getByteValue(),
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        assertArrayEquals(context.getSelectedProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }

    @Test
    public void testAdjustTLSContextTls13() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.getConfig().setKeySharePrivate(
                new BigInteger(ArrayConverter
                        .hexStringToByteArray("03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 0, 1, 2, 3, 4, 5 });
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        context.setServerKeyShareStoreEntry(new KeyShareStoreEntry(NamedGroup.ECDH_X25519, ArrayConverter
                .hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c")));
        context.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(RecordLayerType.RECORD, context));
        handler.adjustTLSContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("EA2F968FD0A381E4B041E6D8DDBF6DA93DE4CEAC862693D3026323E780DB9FC3"),
                context.getHandshakeSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("C56CAE0B1A64467A0E3A3337F8636965787C9A741B0DAB63E503076051BCA15C"),
                context.getClientHandshakeTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("DBF731F5EE037C4494F24701FF074AD4048451C0E2803BC686AF1F2D18E861F5"),
                context.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testAdjustTLSContextTls13PWD() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 0, 1, 2, 3, 4, 5 });
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        context.setServerKeyShareStoreEntry(new KeyShareStoreEntry(
                NamedGroup.BRAINPOOLP256R1,
                ArrayConverter
                        .hexStringToByteArray("9EE17F2ECF74028F6C1FD70DA1D05A4A85975D7D270CAA6B8605F1C6EBB875BA87579167408F7C9E77842C2B3F3368A25FD165637E9B5D57760B0B704659B87420669244AA67CB00EA72C09B84A9DB5BB824FC3982428FCD406963AE080E677A48")));
        context.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(RecordLayerType.RECORD, context));
        handler.adjustTLSContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("09E4B18F6B4F59BD8ADED8E875CD9B9A7694A8C5345EDB3381A47D1F860BF209"),
                context.getHandshakeSecret());
    }
}
