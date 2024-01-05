/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.hpke;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HpkeLabel;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyEncapsulationMechanism;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeMode;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.util.Objects;

/** Implements a subset of the functionality specified in RFC 9180. Needed in ECH */
public class HpkeUtil {

    // variables

    private final HpkeAeadFunction hpkeAeadFunction;

    private final HpkeKeyDerivationFunction hpkeKeyDerivationFunction;

    private final HpkeKeyEncapsulationMechanism hpkeKeyEncapsulationMechanism;

    private byte[] publicKeyReceiver;
    // enc in RFC 9180
    private byte[] publicKeySender;
    private byte[] sharedSecret;
    private byte[] kemContext;
    private byte[] baseNonce;
    private byte[] key;
    private byte[] exporterSecret;
    private byte[] secret;
    private byte[] keyScheduleContext;

    private static final String DEFAULT_PSK = "";
    private static final String DEFAULT_PSK_ID = "";

    public HpkeUtil(
            HpkeAeadFunction hpkeAeadFunction,
            HpkeKeyDerivationFunction hpkeKeyDerivationFunction,
            HpkeKeyEncapsulationMechanism hpkeKeyEncapsulationMechanism) {
        this.hpkeAeadFunction = hpkeAeadFunction;
        this.hpkeKeyDerivationFunction = hpkeKeyDerivationFunction;
        this.hpkeKeyEncapsulationMechanism = hpkeKeyEncapsulationMechanism;
    }

    public HpkeUtil(EchConfig echConfig) {
        this.hpkeAeadFunction = echConfig.getHpkeAeadFunction();
        this.hpkeKeyDerivationFunction = echConfig.getHpkeKeyDerivationFunction();
        this.hpkeKeyEncapsulationMechanism = echConfig.getKem();
    }

    /**
     * Generates a key and prepares an HPKE context for encryption of the ECH
     *
     * @param publicKeyReceiver public key of the receiver
     * @param info additional info to consider for encryption
     * @param keysSender Holds private and public key of the sender
     */
    public HpkeSenderContext setupBaseSender(
            byte[] publicKeyReceiver, byte[] info, KeyShareEntry keysSender)
            throws CryptoException {
        encap(publicKeyReceiver, keysSender);
        HpkeSenderContext hpkeSenderContext =
                generateKeyScheduleSender(
                        HpkeMode.MODE_BASE, sharedSecret, info, DEFAULT_PSK, DEFAULT_PSK_ID);
        return hpkeSenderContext;
    }

    /**
     * Generates a key and prepares an HPKE context for decryption of the ECH
     *
     * @param enc Public key of the sender
     * @param info additional info to consider for encryption
     * @param keysReceiver Holds private and public key of the receiver
     */
    public HpkeReceiverContext setupBaseReceiver(
            byte[] enc, byte[] info, KeyShareEntry keysReceiver) throws CryptoException {
        decap(enc, keysReceiver);
        HpkeReceiverContext hpkeReceiverContext =
                generateKeyScheduleReceiver(
                        HpkeMode.MODE_BASE, sharedSecret, info, DEFAULT_PSK, DEFAULT_PSK_ID);
        return hpkeReceiverContext;
    }

    /**
     * Derives context parameters such as a shared key from a receiver's public key and a sender's
     * private key
     *
     * @param echServerPublicKey receiver's
     * @param keyShareEntry sender's private key
     * @throws CryptoException Should a shared secret not be derivable
     */
    private void encap(byte[] echServerPublicKey, KeyShareEntry keyShareEntry)
            throws CryptoException {
        this.publicKeyReceiver = echServerPublicKey;
        this.publicKeySender = keyShareEntry.getPublicKey().getValue();
        byte[] dh =
                KeyShareCalculator.computeSharedSecret(
                        this.hpkeKeyEncapsulationMechanism.getNamedGroup(),
                        keyShareEntry.getPrivateKey(),
                        echServerPublicKey);
        this.kemContext =
                ArrayConverter.concatenate(
                        keyShareEntry.getPublicKey().getValue(), echServerPublicKey);
        this.sharedSecret = extractAndExpand(dh, kemContext, true);
    }

    /**
     * Derives context parameters such as a shared key from a receiver's private key and a sender's
     * public key
     *
     * @param enc receiver's
     * @param keysReceiver sender's private key
     * @throws CryptoException Should a shared secret not be derivable
     */
    private void decap(byte[] enc, KeyShareEntry keysReceiver) throws CryptoException {
        this.publicKeySender = enc;
        this.publicKeyReceiver = keysReceiver.getPublicKey().getValue();

        // compute shared secret
        byte[] dh =
                KeyShareCalculator.computeSharedSecret(
                        this.hpkeKeyEncapsulationMechanism.getNamedGroup(),
                        keysReceiver.getPrivateKey(),
                        enc);

        // concatenate the two public keys
        this.kemContext = ArrayConverter.concatenate(enc, publicKeyReceiver);

        // save both our public key and the shared secret
        this.sharedSecret = extractAndExpand(dh, kemContext, true);
    }

    private void verifyPskInputs(HpkeMode mode, String psk, String pskId) throws CryptoException {
        boolean gotPsk = (!Objects.equals(psk, DEFAULT_PSK));
        boolean gotPskId = (!Objects.equals(pskId, DEFAULT_PSK_ID));
        if (gotPsk != gotPskId) {
            throw new CryptoException("Inconsistent PSK inputs");
        }
        if (gotPskId && (mode == HpkeMode.MODE_BASE || mode == HpkeMode.MODE_AUTH)) {
            throw new CryptoException("PSK input provided when not needed");
        }
        if (!gotPskId && (mode == HpkeMode.MODE_PSK || mode == HpkeMode.MODE_AUTH_PSK)) {
            throw new CryptoException("Missing required PSK input");
        }
    }

    /**
     * Generates the correct HPKEContext from the given mode, shared secret, and further details
     *
     * @param mode HPKE modes (RFC 9180)
     * @return HPKESenderContext
     * @throws CryptoException Should a key schedule not be derivable
     */
    private HpkeSenderContext generateKeyScheduleSender(
            HpkeMode mode, byte[] sharedSecret, byte[] info, String psk, String pskId)
            throws CryptoException {
        verifyPskInputs(mode, psk, pskId);

        byte[] pskIdHash =
                labeledExtract(
                        HpkeLabel.EMPTY.getBytes(),
                        HpkeLabel.PSK_ID_HASH.getBytes(),
                        pskId.getBytes(),
                        false);
        byte[] infoHash =
                labeledExtract(
                        HpkeLabel.EMPTY.getBytes(), HpkeLabel.INFO_HASH.getBytes(), info, false);
        this.keyScheduleContext =
                ArrayConverter.concatenate(mode.getByteValue(), pskIdHash, infoHash);

        this.secret =
                labeledExtract(sharedSecret, HpkeLabel.SECRET.getBytes(), psk.getBytes(), false);

        this.key =
                labeledExpand(
                        secret,
                        HpkeLabel.KEY.getBytes(),
                        keyScheduleContext,
                        hpkeAeadFunction.getKeyLength(),
                        false);
        this.baseNonce =
                labeledExpand(
                        secret,
                        HpkeLabel.BASE_NONCE.getBytes(),
                        keyScheduleContext,
                        hpkeAeadFunction.getNonceLength(),
                        false);

        this.exporterSecret =
                labeledExpand(
                        secret,
                        HpkeLabel.EXPAND.getBytes(),
                        keyScheduleContext,
                        hpkeKeyDerivationFunction.getHashLength(),
                        false);

        return new HpkeSenderContext(key, baseNonce, 0, exporterSecret, hpkeAeadFunction);
    }

    /**
     * Generates the correct HPKEContext from the given mode, shared secret, and further details
     *
     * @param mode HPKE modes (RFC 9180)
     * @return HPKESenderContext
     * @throws CryptoException Should a key schedule not be derivable
     */
    private HpkeReceiverContext generateKeyScheduleReceiver(
            HpkeMode mode, byte[] sharedSecret, byte[] info, String psk, String pskId)
            throws CryptoException {
        verifyPskInputs(mode, psk, pskId);

        byte[] pskIdHash =
                labeledExtract(
                        HpkeLabel.EMPTY.getBytes(),
                        HpkeLabel.PSK_ID_HASH.getBytes(),
                        pskId.getBytes(),
                        false);
        byte[] infoHash =
                labeledExtract(
                        HpkeLabel.EMPTY.getBytes(), HpkeLabel.INFO_HASH.getBytes(), info, false);
        this.keyScheduleContext =
                ArrayConverter.concatenate(mode.getByteValue(), pskIdHash, infoHash);

        this.secret =
                labeledExtract(sharedSecret, HpkeLabel.SECRET.getBytes(), psk.getBytes(), false);

        this.key =
                labeledExpand(
                        secret,
                        HpkeLabel.KEY.getBytes(),
                        keyScheduleContext,
                        hpkeAeadFunction.getKeyLength(),
                        false);
        this.baseNonce =
                labeledExpand(
                        secret,
                        HpkeLabel.BASE_NONCE.getBytes(),
                        keyScheduleContext,
                        hpkeAeadFunction.getNonceLength(),
                        false);

        this.exporterSecret =
                labeledExpand(
                        secret,
                        HpkeLabel.EXPAND.getBytes(),
                        keyScheduleContext,
                        hpkeKeyDerivationFunction.getHashLength(),
                        false);

        return new HpkeReceiverContext(key, baseNonce, 0, exporterSecret, hpkeAeadFunction);
    }

    /**
     * Constant string for each combination of version, kemId, aeadId, hkdfId. Only uses kemId when
     * used from KEM.
     *
     * @param fromKEM if this method is being called from a KEM
     * @return the suite id as specified in RFC 9180
     */
    private byte[] getSuiteId(boolean fromKEM) {
        if (fromKEM) {
            byte[] kemId = hpkeKeyEncapsulationMechanism.getByteValue();
            return ArrayConverter.concatenate(HpkeLabel.KEM.getBytes(), kemId);
        } else {
            byte[] version = HpkeLabel.HPKE.getBytes();
            byte[] kemId = hpkeKeyEncapsulationMechanism.getByteValue();
            byte[] aeadId = hpkeAeadFunction.getByteValue();
            byte[] hkdfID = hpkeKeyDerivationFunction.getByteValue();
            return ArrayConverter.concatenate(version, kemId, hkdfID, aeadId);
        }
    }

    /**
     * Wrapper around the extract function of the specified HKDF algorithm.
     *
     * @return byte array of extracted secret
     * @throws CryptoException Should the HKDF function not be able to extract
     */
    private byte[] labeledExtract(byte[] salt, byte[] label, byte[] ikm, boolean fromKem)
            throws CryptoException {
        byte[] labeledIkm =
                ArrayConverter.concatenate(
                        HpkeLabel.HPKE_VERSION_1.getBytes(), getSuiteId(fromKem), label, ikm);
        return HKDFunction.extract(hpkeKeyDerivationFunction.getHkdfAlgorithm(), salt, labeledIkm);
    }

    /**
     * Wrapper around the expand function of the specified HKDF algorithm.
     *
     * @return byte array of expanded data
     * @throws CryptoException Should the HKDF function not be able to expand
     */
    private byte[] labeledExpand(byte[] prk, byte[] label, byte[] info, int l, boolean fromKem)
            throws CryptoException {
        byte[] labeledInfo =
                ArrayConverter.concatenate(
                        ArrayConverter.longToBytes(l, 2),
                        HpkeLabel.HPKE_VERSION_1.getBytes(),
                        getSuiteId(fromKem),
                        label,
                        info);
        return HKDFunction.expand(
                hpkeKeyDerivationFunction.getHkdfAlgorithm(), prk, labeledInfo, l);
    }

    /**
     * Combines both the labeled extract and labeled expand function.
     *
     * @return byte array of expanded data
     * @throws CryptoException Should the HKDF function not be able to extract or expand
     */
    private byte[] extractAndExpand(byte[] dh, byte[] kemContext, boolean fromKem)
            throws CryptoException {
        byte[] eaePrk =
                labeledExtract(
                        HpkeLabel.EMPTY.getBytes(),
                        HpkeLabel.EXTRACT_AND_EXPAND.getBytes(),
                        dh,
                        fromKem);
        return labeledExpand(
                eaePrk,
                HpkeLabel.SHARED_SECRET.getBytes(),
                kemContext,
                hpkeKeyEncapsulationMechanism.getSecretLength(),
                fromKem);
    }

    /** Use method in ModifiableVariable when published */
    @Deprecated
    public static int indexOf(byte[] outerArray, byte[] smallerArray) {
        for (int i = 0; i < outerArray.length - smallerArray.length + 1; ++i) {
            boolean found = true;
            for (int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i + j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public byte[] getPublicKeySender() {
        return publicKeySender;
    }

    public byte[] getKemContext() {
        return kemContext;
    }

    public byte[] getBaseNonce() {
        return baseNonce;
    }

    public byte[] getExporterSecret() {
        return exporterSecret;
    }

    public byte[] getSecret() {
        return secret;
    }

    public byte[] getKeyScheduleContext() {
        return keyScheduleContext;
    }

    public byte[] getPublicKeyReceiver() {
        return publicKeyReceiver;
    }

    public byte[] getKey() {
        return key;
    }
}
