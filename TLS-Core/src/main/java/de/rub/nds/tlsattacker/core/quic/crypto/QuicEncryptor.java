/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The QuicEncryptor encrypts {@link QuicPacket} objects. It uses the {@link QuicContext} to get the
 * necessary keys and cipher.
 */
public class QuicEncryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final QuicContext context;

    public QuicEncryptor(QuicContext context) {
        this.context = context;
    }

    public void addHeaderProtectionInitial(InitialPacket packet) throws CryptoException {
        this.addHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateInitialServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateInitialClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void addHeaderProtectionHandshake(HandshakePacket packet) throws CryptoException {
        this.addHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHandshakeServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHandshakeClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void addHeaderProtectionZeroRTT(QuicPacket packet) throws CryptoException {
        this.addHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateZeroRTTServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateZeroRTTClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    public void addHeaderProtectionOneRRT(QuicPacket packet) throws CryptoException {
        this.addHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateOneRTTServerHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateOneRRTClientHeaderProtectionMask(
                        context, packet.getHeaderProtectionSample()));
    }

    private void addHeaderProtection(
            QuicPacket packet,
            byte[] serverHeaderProtectionMask,
            byte[] clientHeaderProtectionMask) {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();
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

        byte encryptedFlags;
        byte flags = packet.getUnprotectedFlags().getValue();
        byte hpMask = headerProtectionMask[0];

        if (QuicPacketType.isShortHeaderPacket(flags)) {
            encryptedFlags = (byte) (flags ^ hpMask & (byte) 0x1f);
        } else {
            encryptedFlags = (byte) (flags ^ hpMask & (byte) 0x0f);
        }
        packet.setProtectedFlags(encryptedFlags);

        byte[] unprotectedPacketNumber = packet.getUnprotectedPacketNumber().getValue();
        byte[] result = new byte[packet.getPacketNumberLength().getValue()];
        for (int i = 0; i < packet.getPacketNumberLength().getValue(); i++) {
            result[i] = (byte) (unprotectedPacketNumber[i] ^ headerProtectionMask[i + 1]);
        }
        packet.setProtectedPacketNumber(result);
    }

    public void encryptInitialPacket(InitialPacket packet) throws CryptoException {
        this.encrypt(
                packet,
                context.getInitialServerIv(),
                context.getInitialServerKey(),
                context.getInitialClientIv(),
                context.getInitialClientKey(),
                context.getInitialAeadCipher());
    }

    public void encryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        this.encrypt(
                packet,
                context.getHandshakeServerIv(),
                context.getHandshakeServerKey(),
                context.getHandshakeClientIv(),
                context.getHandshakeClientKey(),
                context.getAeadCipher());
    }

    public void encryptOneRRTPacket(QuicPacket packet) throws CryptoException {
        this.encrypt(
                packet,
                context.getApplicationServerIv(),
                context.getApplicationServerKey(),
                context.getApplicationClientIv(),
                context.getApplicationClientKey(),
                context.getAeadCipher());
    }

    public void encryptZeroRTTPacket(QuicPacket packet) throws CryptoException {
        this.encrypt(
                packet,
                context.getZeroRTTServerIv(),
                context.getZeroRTTServerKey(),
                context.getZeroRTTClientIv(),
                context.getZeroRTTClientKey(),
                context.getZeroRTTAeadCipher());
    }

    private void encrypt(
            QuicPacket packet,
            byte[] serverIv,
            byte[] serverKey,
            byte[] clientIv,
            byte[] clientKey,
            Cipher cipher)
            throws CryptoException {
        ConnectionEndType connectionEndType = context.getTalkingConnectionEndType();
        byte[] encryptionIv;
        byte[] encryptionKey;

        switch (connectionEndType) {
            case SERVER:
                encryptionIv = serverIv;
                encryptionKey = serverKey;
                break;
            case CLIENT:
                encryptionIv = clientIv;
                encryptionKey = clientKey;
                break;
            default:
                LOGGER.error("Unknown connectionEndType" + connectionEndType);
                return;
        }

        byte[] decryptedPayload = packet.getUnprotectedPayload().getValue();
        byte[] nonce = new byte[12];
        byte[] paddedPacketNumber = new byte[12];

        for (int i = 0; i < (12 - packet.getUnprotectedPacketNumber().getValue().length); i++) {
            paddedPacketNumber[i] = 0x00;
        }
        for (int i = (12 - packet.getUnprotectedPacketNumber().getValue().length), x = 0;
                i < 12;
                i++, x++) {
            paddedPacketNumber[i] = packet.getUnprotectedPacketNumber().getValue()[x];
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (encryptionIv[i] ^ paddedPacketNumber[i]);
        }

        byte[] associatedData = packet.unprotectedHeaderHelper.toByteArray();

        try {
            byte[] encryptedPayload =
                    aeadEncrypt(associatedData, decryptedPayload, nonce, encryptionKey, cipher);
            packet.setProtectedPayload(encryptedPayload);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt " + packet.getPacketType().getName(), ex);
        } catch (InvalidAlgorithmParameterException ex) {
            LOGGER.info("Ignoring InvalidArgumentException");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] aeadEncrypt(
            byte[] associatedData, byte[] plaintext, byte[] nonce, byte[] key, Cipher aeadCipher)
            throws InvalidKeyException,
                    IllegalBlockSizeException,
                    BadPaddingException,
                    NoSuchPaddingException,
                    NoSuchAlgorithmException,
                    InvalidAlgorithmParameterException {
        AlgorithmParameterSpec parameterSpec;
        String algo;
        Cipher _cipher = Cipher.getInstance(aeadCipher.getAlgorithm());
        if (aeadCipher.getAlgorithm().equals("ChaCha20-Poly1305")) {
            algo = "ChaCha20";
            parameterSpec = new IvParameterSpec(nonce);
        } else {
            algo = "AES";
            parameterSpec = new GCMParameterSpec(128, nonce);
        }
        _cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algo), parameterSpec);
        _cipher.updateAAD(associatedData);
        return _cipher.doFinal(plaintext);
    }
}
