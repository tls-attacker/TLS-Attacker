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
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ServerHelloHandlerTest
        extends AbstractProtocolMessageHandlerTest<ServerHelloMessage, ServerHelloHandler> {

    public ServerHelloHandlerTest() {
        super(ServerHelloMessage::new, ServerHelloHandler::new);
    }

    /** Test of adjustContext method, of class ServerHelloHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustContext(message);
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 5}, context.getServerRandom());
        assertSame(CompressionMethod.DEFLATE, context.getSelectedCompressionMethod());
        assertArrayEquals(new byte[] {6, 6, 6}, context.getServerSessionId());
        assertArrayEquals(
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue(),
                context.getSelectedCipherSuite().getByteValue());
        assertArrayEquals(
                ProtocolVersion.TLS12.getValue(), context.getSelectedProtocolVersion().getValue());
    }

    @Test
    public void testadjustContextTls13() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.getConfig()
                .setKeySharePrivate(
                        new BigInteger(
                                ArrayConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        context.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(
                        NamedGroup.ECDH_X25519,
                        ArrayConverter.hexStringToByteArray(
                                "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c")));
        context.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "EA2F968FD0A381E4B041E6D8DDBF6DA93DE4CEAC862693D3026323E780DB9FC3"),
                context.getHandshakeSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "C56CAE0B1A64467A0E3A3337F8636965787C9A741B0DAB63E503076051BCA15C"),
                context.getClientHandshakeTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "DBF731F5EE037C4494F24701FF074AD4048451C0E2803BC686AF1F2D18E861F5"),
                context.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testadjustContextTls13PWD() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(
                CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        context.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(
                        NamedGroup.BRAINPOOLP256R1,
                        ArrayConverter.hexStringToByteArray(
                                "9EE17F2ECF74028F6C1FD70DA1D05A4A85975D7D270CAA6B8605F1C6EBB875BA87579167408F7C9E77842C2B3F3368A25FD165637E9B5D57760B0B704659B87420669244AA67CB00EA72C09B84A9DB5BB824FC3982428FCD406963AE080E677A48")));
        context.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "09E4B18F6B4F59BD8ADED8E875CD9B9A7694A8C5345EDB3381A47D1F860BF209"),
                context.getHandshakeSecret());
    }
}
