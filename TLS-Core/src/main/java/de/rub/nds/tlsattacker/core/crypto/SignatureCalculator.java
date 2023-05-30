/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] generateSignature(
            byte[] toBeSigned, SignatureAndHashAlgorithm algorithm, Chooser chooser)
            throws CryptoException {
        PrivateKey privateKey = null;

        if (chooser.getSelectedProtocolVersion() == ProtocolVersion.SSL3
                || chooser.getSelectedProtocolVersion() == ProtocolVersion.TLS10
                || chooser.getSelectedProtocolVersion() == ProtocolVersion.TLS11
                || chooser.getSelectedProtocolVersion() == ProtocolVersion.DTLS10) {
            KeyExchangeAlgorithm keyExchangeAlgorithm =
                    AlgorithmResolver.getKeyExchangeAlgorithm(chooser.getSelectedCipherSuite());
            if (keyExchangeAlgorithm != null) {

                if (keyExchangeAlgorithm.name().contains("RSA")) {
                    algorithm = SignatureAndHashAlgorithm.RSA_NONE;
                    toBeSigned =
                            ArrayConverter.concatenate(
                                    MD5Utils.md5(toBeSigned), SHA1Utils.sha1(toBeSigned));
                    privateKey = KeyGenerator.getRSAPrivateKey(chooser);
                } else if (keyExchangeAlgorithm.name().contains("ECDSA")) {
                    algorithm = SignatureAndHashAlgorithm.ECDSA_SHA1;
                    KeyGenerator.getECPrivateKey(chooser);
                } else if (keyExchangeAlgorithm.name().contains("DSS")) {
                    algorithm = SignatureAndHashAlgorithm.DSA_SHA1;
                    privateKey = KeyGenerator.getDSAPrivateKey(chooser);
                } else {
                    throw new UnsupportedOperationException(
                            "Cipher suite not supported - Check Debug Log");
                }
            }
        }
        if (privateKey == null) {
            switch (algorithm.getSignatureAlgorithm()) {
                case ANONYMOUS:
                    return new byte[0];
                case DSA:
                    privateKey = KeyGenerator.getDSAPrivateKey(chooser);
                    break;
                case ECDSA:
                    privateKey = KeyGenerator.getECPrivateKey(chooser);
                    break;
                case RSA:
                case RSA_PSS_PSS:
                case RSA_PSS_RSAE:
                    privateKey = KeyGenerator.getRSAPrivateKey(chooser);
                    break;
                case GOSTR34102001:
                    privateKey = KeyGenerator.getGost01PrivateKey(chooser);
                    break;
                case GOSTR34102012_256:
                case GOSTR34102012_512:
                    privateKey = KeyGenerator.getGost12PrivateKey(chooser);
                    break;
                default:
                    throw new UnsupportedOperationException(
                            "Unknown SignatureAlgorithm:"
                                    + algorithm.getSignatureAlgorithm().name());
            }
        }
        try {
            LOGGER.debug(
                    "Creating Signature with "
                            + algorithm.getSignatureAlgorithm().name()
                            + " over "
                            + ArrayConverter.bytesToHexString(toBeSigned)
                            + " with the PrivateKey:"
                            + privateKey.toString());
            Signature instance = Signature.getInstance(algorithm.getJavaName());
            algorithm.setupSignature(instance);
            instance.initSign(privateKey, chooser.getContext().getBadSecureRandom());
            instance.update(toBeSigned);
            return instance.sign();
        } catch (SignatureException
                | InvalidKeyException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | IllegalArgumentException ex) {
            throw new CryptoException("Could not sign Data", ex);
        }
    }

    private SignatureCalculator() {}
}
