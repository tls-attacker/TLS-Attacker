/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
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
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 5}, tlsContext.getServerRandom());
        assertSame(CompressionMethod.DEFLATE, tlsContext.getSelectedCompressionMethod());
        assertArrayEquals(new byte[] {6, 6, 6}, tlsContext.getServerSessionId());
        assertArrayEquals(
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue(),
                tlsContext.getSelectedCipherSuite().getByteValue());
        assertArrayEquals(
                ProtocolVersion.TLS12.getValue(),
                tlsContext.getSelectedProtocolVersion().getValue());
    }

    @Test
    public void testadjustContextTls13() {
        ServerHelloMessage message = new ServerHelloMessage();
        tlsContext
                .getConfig()
                .setDefaultKeySharePrivateKey(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                DataConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        tlsContext.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(
                        NamedGroup.ECDH_X25519,
                        DataConverter.hexStringToByteArray(
                                "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c")));
        tlsContext.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "EA2F968FD0A381E4B041E6D8DDBF6DA93DE4CEAC862693D3026323E780DB9FC3"),
                tlsContext.getHandshakeSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "C56CAE0B1A64467A0E3A3337F8636965787C9A741B0DAB63E503076051BCA15C"),
                tlsContext.getClientHandshakeTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "DBF731F5EE037C4494F24701FF074AD4048451C0E2803BC686AF1F2D18E861F5"),
                tlsContext.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testadjustContextTls13PWD() {
        ServerHelloMessage message = new ServerHelloMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(
                CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        tlsContext.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(
                        NamedGroup.BRAINPOOLP256R1,
                        DataConverter.hexStringToByteArray(
                                "9EE17F2ECF74028F6C1FD70DA1D05A4A85975D7D270CAA6B8605F1C6EBB875BA87579167408F7C9E77842C2B3F3368A25FD165637E9B5D57760B0B704659B87420669244AA67CB00EA72C09B84A9DB5BB824FC3982428FCD406963AE080E677A48")));
        tlsContext.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "09E4B18F6B4F59BD8ADED8E875CD9B9A7694A8C5345EDB3381A47D1F860BF209"),
                tlsContext.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13PQ() {
        ServerHelloMessage message = new ServerHelloMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());

        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMlKemKeyShare(
                NamedGroup.MLKEM768, clientEntry, new SecureRandom());

        tlsContext
                .getClientMlKemPrivateKeys()
                .put(NamedGroup.MLKEM768, clientEntry.getMlKemPrivateKeyContainer());

        MlKemEncapsulation encapsResult =
                KeyShareCalculator.mlKemEncaps(
                        NamedGroup.MLKEM768,
                        clientEntry.getMlKemPublicKey().getValue(),
                        new SecureRandom());

        tlsContext.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(NamedGroup.MLKEM768, encapsResult.getCiphertext()));
        tlsContext.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);

        assertNotNull(tlsContext.getHandshakeSecret());
        assertNotNull(tlsContext.getClientHandshakeTrafficSecret());
        assertNotNull(tlsContext.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testadjustContextTls13HybridPQ() {
        ServerHelloMessage message = new ServerHelloMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());

        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMlKemKeyShare(
                NamedGroup.MLKEM768, clientEntry, new SecureRandom());

        tlsContext
                .getClientMlKemPrivateKeys()
                .put(NamedGroup.X25519_MLKEM768, clientEntry.getMlKemPrivateKeyContainer());

        MlKemEncapsulation encapsResult =
                KeyShareCalculator.mlKemEncaps(
                        NamedGroup.MLKEM768,
                        clientEntry.getMlKemPublicKey().getValue(),
                        new SecureRandom());

        tlsContext
                .getConfig()
                .setDefaultKeySharePrivateKey(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                DataConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));

        tlsContext.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(
                        NamedGroup.X25519_MLKEM768,
                        PQUtils.concatenateHybridKeyShare(
                                NamedGroup.X25519_MLKEM768,
                                DataConverter.hexStringToByteArray(
                                        "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"),
                                encapsResult.getCiphertext())));
        tlsContext.addNegotiatedExtension(ExtensionType.KEY_SHARE);
        handler.adjustContext(message);

        assertNotNull(tlsContext.getHandshakeSecret());
        assertNotNull(tlsContext.getClientHandshakeTrafficSecret());
        assertNotNull(tlsContext.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testadjustContextTls13HybridPQReadsBothKeyShareComponents() {
        NamedGroup namedGroup = NamedGroup.X25519_MLKEM768;
        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMlKemKeyShare(
                NamedGroup.MLKEM768, clientEntry, new SecureRandom());
        byte[] ciphertext =
                KeyShareCalculator.mlKemEncaps(
                                NamedGroup.MLKEM768,
                                clientEntry.getMlKemPublicKey().getValue(),
                                new SecureRandom())
                        .getCiphertext();
        byte[] classicalPublicKey =
                DataConverter.hexStringToByteArray(
                        "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c");
        // fill to fail test if hybrid PQ component fields are not read
        byte[] dummyKeyShare =
                PQUtils.concatenateHybridKeyShare(
                        namedGroup,
                        fillArray(classicalPublicKey.length, (byte) 0x42),
                        fillArray(ciphertext.length, (byte) 0x43));

        byte[] expected =
                handshakeSecretFor(
                        new KeyShareStoreEntry(
                                namedGroup,
                                PQUtils.concatenateHybridKeyShare(
                                        namedGroup, classicalPublicKey, ciphertext)),
                        clientEntry);

        KeyShareEntry serverEntry = new KeyShareEntry();
        serverEntry.setGroupConfig(namedGroup);
        serverEntry.setPublicKey(dummyKeyShare);
        serverEntry.setDhPublicKey(classicalPublicKey);
        serverEntry.setMlKemCiphertext(ciphertext);

        assertNotNull(expected);
        assertArrayEquals(
                expected, handshakeSecretFor(new KeyShareStoreEntry(serverEntry), clientEntry));
        assertFalse(
                Arrays.equals(
                        expected,
                        handshakeSecretFor(
                                new KeyShareStoreEntry(namedGroup, dummyKeyShare), clientEntry)));
    }

    @Test
    public void testadjustContextTls13PQReadsMlKemCiphertext() {
        NamedGroup namedGroup = NamedGroup.MLKEM768;
        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMlKemKeyShare(namedGroup, clientEntry, new SecureRandom());
        byte[] ciphertext =
                KeyShareCalculator.mlKemEncaps(
                                namedGroup,
                                clientEntry.getMlKemPublicKey().getValue(),
                                new SecureRandom())
                        .getCiphertext();
        // fill to fail test if mlKemCiphertext field is not read
        byte[] dummyCiphertext = fillArray(ciphertext.length, (byte) 0x43);

        byte[] expected =
                handshakeSecretFor(new KeyShareStoreEntry(namedGroup, ciphertext), clientEntry);

        KeyShareEntry serverEntry = new KeyShareEntry();
        serverEntry.setGroupConfig(namedGroup);
        serverEntry.setPublicKey(dummyCiphertext);
        serverEntry.setMlKemCiphertext(ciphertext);

        assertNotNull(expected);
        assertArrayEquals(
                expected, handshakeSecretFor(new KeyShareStoreEntry(serverEntry), clientEntry));
        assertFalse(
                Arrays.equals(
                        expected,
                        handshakeSecretFor(
                                new KeyShareStoreEntry(namedGroup, dummyCiphertext), clientEntry)));
    }

    private static byte[] handshakeSecretFor(
            KeyShareStoreEntry serverKeyShare, KeyShareEntry clientEntry) {
        TlsContext context =
                new Context(new State(new Config()), new OutboundConnection()).getTlsContext();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getClientMlKemPrivateKeys()
                .put(serverKeyShare.getGroup(), clientEntry.getMlKemPrivateKeyContainer());
        context.getConfig()
                .setDefaultKeySharePrivateKey(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                DataConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        context.setServerKeyShareStoreEntry(serverKeyShare);
        context.addNegotiatedExtension(ExtensionType.KEY_SHARE);

        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        new ServerHelloHandler(context).adjustContext(message);

        return context.getHandshakeSecret();
    }

    private static byte[] fillArray(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
