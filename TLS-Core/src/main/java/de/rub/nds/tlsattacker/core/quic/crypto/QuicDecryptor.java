/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicDecryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final QuicContext context;

    public QuicDecryptor(QuicContext context) {
        this.context = context;
    }

    public void removeHeaderProtection(QuicPacket packet) throws CryptoException {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();
        byte[] clientHeaderProtectionMask;
        byte[] serverHeaderProtectionMask;

        switch (packet.getPacketType()) {
            case INITIAL_PACKET:
                clientHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateInitialClientHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                serverHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateInitialServerHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                break;
            case HANDSHAKE_PACKET:
                clientHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateHandshakeClientHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                serverHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateHandshakeServerHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                break;
            case ONE_RTT_PACKET:
                clientHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateApplicationClientHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                serverHeaderProtectionMask =
                        QuicPacketCryptoComputations.generateApplicationServerHeaderProtectionMask(
                                context, packet.getHeaderProtectionSample());
                break;
            default:
                return;
        }

        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (context.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }

        byte[] headerProtectionMask;

        switch (connectionEndType) {
            case SERVER:
                headerProtectionMask = serverHeaderProtectionMask;
                break;
            case CLIENT:
                headerProtectionMask = clientHeaderProtectionMask;
                break;
            default:
                LOGGER.error("Unknown connectionEndType" + connectionEndType);
                return;
        }

        byte unprotectedFlags;
        byte flags = packet.getProtectedFlags().getValue();
        byte hpMask = headerProtectionMask[0];
        if (QuicPacketType.isShortHeaderPacket(flags)) {
            unprotectedFlags = (byte) (flags ^ hpMask & (byte) 0x1f);
        } else {
            unprotectedFlags = (byte) (flags ^ hpMask & (byte) 0x0f);
        }
        packet.setUnprotectedFlags(unprotectedFlags);

        // remove protection from Packet Number

        // see RFC 9001 - 5.4.1.  Header Protection Application
        int length = (unprotectedFlags & 0x03) + 1;
        packet.setPacketNumberLength(length);

        byte[] protectedPacketNumber = new byte[length];
        System.arraycopy(
                packet.getProtectedPacketNumberAndPayload().getValue(),
                0,
                protectedPacketNumber,
                0,
                length);
        packet.setProtectedPacketNumber(protectedPacketNumber);

        byte[] result = new byte[packet.getPacketNumberLength().getValue()];
        for (int i = 0; i < packet.getPacketNumberLength().getValue(); i++) {
            result[i] = (byte) (headerProtectionMask[i + 1] ^ protectedPacketNumber[i]);
        }

        try {
            packet.protectedHeaderHelper.write(result);
            packet.setUnprotectedPacketNumber(result);
            restorePacketNumber(packet);
            // recovered packet number is only used for nonce computation

        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    public byte[] aeadDecrypt(
            byte[] associatedData, byte[] ciphertext, byte[] nonce, byte[] key, Cipher aeadCipher)
            throws InvalidAlgorithmParameterException,
                    InvalidKeyException,
                    IllegalBlockSizeException,
                    BadPaddingException {
        String algo;
        AlgorithmParameterSpec parameterSpec;
        if (aeadCipher.getAlgorithm().equals("ChaCha20-Poly1305")) {
            algo = "ChaCha20";
            parameterSpec = new IvParameterSpec(nonce);
        } else {
            algo = "AES";
            parameterSpec = new GCMParameterSpec(128, nonce);
        }
        aeadCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algo), parameterSpec);
        aeadCipher.updateAAD(associatedData);
        return aeadCipher.doFinal(ciphertext);
    }

    public void decryptInitialPacket(InitialPacket packet) throws CryptoException {
        this.decrypt(
                packet,
                context.getInitialServerIv(),
                context.getInitialServerKey(),
                context.getInitialClientIv(),
                context.getInitialClientKey(),
                context.getInitialAeadCipher());
    }

    public void decryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        this.decrypt(
                packet,
                context.getHandshakeServerIv(),
                context.getHandshakeServerKey(),
                context.getHandshakeClientIv(),
                context.getHandshakeClientKey(),
                context.getAeadCipher());
    }

    public void decryptApplicationPacket(QuicPacket packet) throws CryptoException {
        this.decrypt(
                packet,
                context.getApplicationServerIv(),
                context.getApplicationServerKey(),
                context.getApplicationClientIv(),
                context.getApplicationClientKey(),
                context.getAeadCipher());
    }

    public void decrypt(
            QuicPacket packet,
            byte[] serverIv,
            byte[] serverKey,
            byte[] clientIv,
            byte[] clientKey,
            Cipher cipher)
            throws CryptoException {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();

        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (context.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }

        byte[] decryptionIv;
        byte[] decryptionKey;

        switch (connectionEndType) {
            case SERVER:
                decryptionIv = serverIv;
                decryptionKey = serverKey;
                break;
            case CLIENT:
                decryptionIv = clientIv;
                decryptionKey = clientKey;
                break;
            default:
                LOGGER.error("Unknown connectionEndType" + connectionEndType);
                return;
        }

        byte[] encryptedPayload =
                new byte
                        [packet.getPacketLength().getValue()
                                - packet.getPacketNumberLength().getValue()];
        System.arraycopy(
                packet.getProtectedPacketNumberAndPayload().getValue(),
                packet.getPacketNumberLength().getValue(),
                encryptedPayload,
                0,
                packet.getPacketLength().getValue() - packet.getPacketNumberLength().getValue());

        byte[] nonce = new byte[12];
        byte[] paddedPacketNumber = new byte[12];

        for (int i = 0; i < (12 - packet.getRestoredPacketNumber().getValue().length); i++) {
            paddedPacketNumber[i] = 0x00;
        }
        for (int i = (12 - packet.getRestoredPacketNumber().getValue().length), x = 0;
                i < 12;
                i++, x++) {
            paddedPacketNumber[i] = packet.getRestoredPacketNumber().getValue()[x];
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (decryptionIv[i] ^ paddedPacketNumber[i]);
        }

        // 5.3. AEAD Usage https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
        // The associated data, A, for the AEAD is the contents of the QUIC header, starting from
        // the
        // first byte of either the short or long header, up to and including the unprotected packet
        // number.
        byte[] associatedData =
                new byte
                        [packet.offsetToPacketNumber
                                + packet.getUnprotectedPacketNumber().getValue().length];

        System.arraycopy(
                packet.completeUnprotectedHeader.getValue(),
                0,
                associatedData,
                0,
                packet.offsetToPacketNumber
                        + packet.getUnprotectedPacketNumber().getValue().length);

        try {
            byte[] decryptedPayload =
                    aeadDecrypt(associatedData, encryptedPayload, nonce, decryptionKey, cipher);
            packet.setUnprotectedPayload(decryptedPayload);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | IllegalArgumentException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Could not decrypt " + packet.getPacketType().getName(), ex);
        }
    }

    protected void restorePacketNumber(QuicPacket packet) {
        int largest_Pn = 0;
        if (packet.getPacketType() == QuicPacketType.INITIAL_PACKET) {
            if (!context.getReceivedInitialPacketNumbers().isEmpty()) {
                largest_Pn = context.getReceivedInitialPacketNumbers().getLast();
            }
        } else if (packet.getPacketType() == QuicPacketType.HANDSHAKE_PACKET) {
            if (!context.getReceivedHandshakePacketNumbers().isEmpty()) {
                largest_Pn = context.getReceivedHandshakePacketNumbers().getLast();
            }
        } else if (packet.getPacketType() == QuicPacketType.ONE_RTT_PACKET) {
            if (!context.getReceivedOneRTTPacketNumbers().isEmpty()) {
                largest_Pn = context.getReceivedOneRTTPacketNumbers().getLast();
            }
        }

        int truncated_Pn =
                ArrayConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue());
        int pn_nBits = packet.getPacketNumberLength().getValue();

        long decodedPn = packet.decodePacketNumber(truncated_Pn, largest_Pn, pn_nBits);
        LOGGER.debug(
                "decoded pktNumber: {}, raw pktNumber: {}",
                decodedPn,
                ArrayConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));

        packet.setRestoredPacketNumber((int) decodedPn);
        packet.setPlainPacketNumber((int) decodedPn);

        if (packet.getUnprotectedPacketNumber().getValue().length
                >= packet.getRestoredPacketNumber().getValue().length) {
            packet.setRestoredPacketNumber(packet.getUnprotectedPacketNumber().getValue());
            packet.setPlainPacketNumber(
                    ArrayConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));
        }
    }
}
