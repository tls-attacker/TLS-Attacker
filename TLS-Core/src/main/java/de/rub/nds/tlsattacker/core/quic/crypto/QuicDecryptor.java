/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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

/**
 * The QuicDecryptor decrypts {@link QuicPacket} objects. It uses the {@link QuicContext} to get the
 * necessary keys and cipher.
 */
public class QuicDecryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final QuicContext context;

    public QuicDecryptor(QuicContext context) {
        this.context = context;
    }

    public void removeHeaderProtectionInitial(InitialPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateInitialServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateInitialClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionHandshake(HandshakePacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHandshakeServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHandshakeClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionZeroRTT(QuicPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateZeroRTTServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateZeroRTTClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionOneRTT(QuicPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateOneRTTServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateOneRRTClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtection(
            QuicPacket packet,
            byte[] serverHeaderProtectionMask,
            byte[] clientHeaderProtectionMask) {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();
        byte[] headerProtectionMask;

        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (context.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }

        switch (connectionEndType) {
            case SERVER:
                headerProtectionMask = serverHeaderProtectionMask;
                break;
            case CLIENT:
                headerProtectionMask = clientHeaderProtectionMask;
                break;
            default:
                LOGGER.error("Unknown connectionEndType: {}", connectionEndType);
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
        packet.protectedHeaderHelper.write(result);
        packet.setUnprotectedPacketNumber(result);
        restorePacketNumber(packet);
    }

    private void restorePacketNumber(QuicPacket packet) {
        int largest_Pn = 0;
        switch (packet.getPacketType()) {
            case INITIAL_PACKET:
                if (!context.getReceivedInitialPacketNumbers().isEmpty()) {
                    largest_Pn = context.getReceivedInitialPacketNumbers().getLast();
                }
                break;
            case HANDSHAKE_PACKET:
                if (!context.getReceivedHandshakePacketNumbers().isEmpty()) {
                    largest_Pn = context.getReceivedHandshakePacketNumbers().getLast();
                }
                break;
            case ONE_RTT_PACKET:
                if (!context.getReceivedOneRTTPacketNumbers().isEmpty()) {
                    largest_Pn = context.getReceivedOneRTTPacketNumbers().getLast();
                }
                break;
            default:
                break;
        }

        int truncated_Pn = DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue());
        int pn_nBits = packet.getPacketNumberLength().getValue();
        long decodedPn = packet.decodePacketNumber(truncated_Pn, largest_Pn, pn_nBits);
        LOGGER.debug(
                "Decoded pktNumber: {}, raw pktNumber: {}",
                decodedPn,
                DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));

        packet.setRestoredPacketNumber((int) decodedPn);
        packet.setPlainPacketNumber((int) decodedPn);

        if (packet.getUnprotectedPacketNumber().getValue().length
                >= packet.getRestoredPacketNumber().getValue().length) {
            packet.setRestoredPacketNumber(packet.getUnprotectedPacketNumber().getValue());
            packet.setPlainPacketNumber(
                    DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));
        }
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

    public void decryptOneRTTPacket(QuicPacket packet) throws CryptoException {
        this.decrypt(
                packet,
                context.getApplicationServerIv(),
                context.getApplicationServerKey(),
                context.getApplicationClientIv(),
                context.getApplicationClientKey(),
                context.getAeadCipher());
    }

    private void decrypt(
            QuicPacket packet,
            byte[] serverIv,
            byte[] serverKey,
            byte[] clientIv,
            byte[] clientKey,
            Cipher cipher)
            throws CryptoException {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();
        byte[] decryptionIv;
        byte[] decryptionKey;

        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (context.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }

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
                LOGGER.error("Unknown connectionEndType: {}", connectionEndType);
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

    public byte[] aeadDecrypt(
            byte[] associatedData, byte[] ciphertext, byte[] nonce, byte[] key, Cipher aeadCipher)
            throws InvalidAlgorithmParameterException,
                    InvalidKeyException,
                    IllegalBlockSizeException,
                    BadPaddingException {
        AlgorithmParameterSpec parameterSpec;
        String algo;
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
}
