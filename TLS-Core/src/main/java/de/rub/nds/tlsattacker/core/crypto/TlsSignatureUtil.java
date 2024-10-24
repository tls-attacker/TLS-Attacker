/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.hash.HashCalculator;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.protocol.crypto.signature.DsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.EcdsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.protocol.crypto.signature.RsaSsaPssSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureVerificationComputations;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsSignatureUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignatureCalculator calculator;

    public TlsSignatureUtil() {
        this.calculator = new SignatureCalculator();
    }

    public void computeSignature(
            Chooser chooser,
            SignatureAndHashAlgorithm algorithm,
            byte[] toBeHashedAndSigned,
            SignatureComputations computations) {

        ProtocolVersion selectedProtocolVersion = chooser.getSelectedProtocolVersion();
        switch (algorithm.getSignatureAlgorithm()) {
            case DSA:
                if (!(computations instanceof DsaSignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type DsaSignatureComputations for "
                                    + algorithm);
                }
                HashAlgorithm hashAlgorithm = algorithm.getHashAlgorithm();
                if (selectedProtocolVersion == ProtocolVersion.DTLS10
                        || selectedProtocolVersion == ProtocolVersion.SSL3
                        || selectedProtocolVersion == ProtocolVersion.TLS10
                        || selectedProtocolVersion == ProtocolVersion.TLS11) {
                    hashAlgorithm = HashAlgorithm.SHA1;
                }
                computeDsaSignature(
                        chooser,
                        hashAlgorithm,
                        toBeHashedAndSigned,
                        (DsaSignatureComputations) computations);
                break;
            case ECDSA:
                if (!(computations instanceof EcdsaSignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type EcdsaSignatureComputations for "
                                    + algorithm);
                }
                computeEcdsaSignature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHashedAndSigned,
                        (EcdsaSignatureComputations) computations);
                break;
            case RSA_PKCS1:
                if (!(computations instanceof RsaPkcs1SignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type RsaPkcs1SignatureComputations for "
                                    + algorithm);
                }
                hashAlgorithm = algorithm.getHashAlgorithm();
                if (selectedProtocolVersion == ProtocolVersion.DTLS10
                        || selectedProtocolVersion == ProtocolVersion.SSL3
                        || selectedProtocolVersion == ProtocolVersion.TLS10
                        || selectedProtocolVersion == ProtocolVersion.TLS11) {
                    hashAlgorithm = HashAlgorithm.NONE;
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.writeBytes(
                            HashCalculator.compute(toBeHashedAndSigned, HashAlgorithm.MD5));
                    outputStream.writeBytes(
                            HashCalculator.compute(toBeHashedAndSigned, HashAlgorithm.SHA1));
                    toBeHashedAndSigned = outputStream.toByteArray();
                }
                computeRsaPkcs1Signature(
                        chooser,
                        hashAlgorithm,
                        toBeHashedAndSigned,
                        (RsaPkcs1SignatureComputations) computations);
                break;
            case RSA_SSA_PSS:
                if (!(computations instanceof RsaSsaPssSignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type RsaPssSignatureComputations for "
                                    + algorithm);
                }
                computeRsaPssSignature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHashedAndSigned,
                        (RsaSsaPssSignatureComputations) computations);
                break;
            case ED25519:
            case ED448:
            case GOSTR34102001:
            case GOSTR34102012_256:
                throw new UnsupportedOperationException(
                        "Not implemented yet: " + algorithm.getSignatureAlgorithm());
            default:
                throw new UnsupportedOperationException(
                        "Not implemented: " + algorithm.getSignatureAlgorithm());
        }
    }

    public void verifySignature(
            Chooser chooser,
            SignatureAndHashAlgorithm algorithm,
            byte[] signature,
            byte[] toBeSigned,
            SignatureVerificationComputations computations) {
        switch (algorithm.getSignatureAlgorithm()) {
            case DSA:
            case ECDSA:
            case ED25519:
            case ED448:
            case GOSTR34102001:
            case GOSTR34102012_256:
            default:
                throw new UnsupportedOperationException("Not implemented");
        }
    }

    private void computeEcdsaSignature(
            Chooser chooser,
            HashAlgorithm algorithm,
            byte[] toBeHasedAndSigned,
            EcdsaSignatureComputations computations) {
        BigInteger nonce;
        BigInteger privateKey =
                chooser.getContext()
                        .getTlsContext()
                        .getTalkingX509Context()
                        .getChooser()
                        .getSubjectEcPrivateKey();

        nonce = chooser.getConfig().getDefaultEcdsaNonce();
        calculator.computeEcdsaSignature(
                computations,
                new EcdsaPrivateKey(
                        privateKey,
                        nonce,
                        chooser.getContext()
                                .getTlsContext()
                                .getTalkingX509Context()
                                .getChooser()
                                .getSubjectNamedCurve()
                                .getParameters()),
                toBeHasedAndSigned,
                algorithm);
    }

    private void computeDsaSignature(
            Chooser chooser,
            HashAlgorithm algorithm,
            byte[] toBeHasedAndSigned,
            DsaSignatureComputations computations) {

        X509Chooser x509chooser =
                chooser.getContext().getTlsContext().getTalkingX509Context().getChooser();
        BigInteger privateKey = x509chooser.getSubjectDsaPrivateKey();
        BigInteger primeModulusP = x509chooser.getDsaPrimeP();
        BigInteger primeQ = x509chooser.getDsaPrimeQ();
        BigInteger generator = x509chooser.getDsaGenerator();
        BigInteger nonce = chooser.getConfig().getDefaultDsaNonce();
        calculator.computeDsaSignature(
                computations,
                new DsaPrivateKey(primeQ, privateKey, nonce, generator, primeModulusP),
                toBeHasedAndSigned,
                algorithm);
    }

    private void computeRsaPkcs1Signature(
            Chooser chooser,
            HashAlgorithm algorithm,
            byte[] toBeHasedAndSigned,
            RsaPkcs1SignatureComputations computations) {

        BigInteger modulus =
                chooser.getContext()
                        .getTlsContext()
                        .getTalkingX509Context()
                        .getChooser()
                        .getSubjectRsaModulus();
        BigInteger privateKey =
                chooser.getContext()
                        .getTlsContext()
                        .getTalkingX509Context()
                        .getChooser()
                        .getSubjectRsaPrivateKey();
        calculator.computeRsaPkcs1Signature(
                computations,
                new RsaPrivateKey(privateKey, modulus),
                toBeHasedAndSigned,
                algorithm);
    }

    private void computeRsaPssSignature(
            Chooser chooser,
            HashAlgorithm algorithm,
            byte[] toBeHasedAndSigned,
            RsaSsaPssSignatureComputations computations) {

        BigInteger modulus =
                chooser.getContext()
                        .getTlsContext()
                        .getTalkingX509Context()
                        .getChooser()
                        .getSubjectRsaModulus();
        BigInteger privateKey =
                chooser.getContext()
                        .getTlsContext()
                        .getTalkingX509Context()
                        .getChooser()
                        .getSubjectRsaPrivateKey();
        byte[] salt = chooser.getConfig().getDefaultRsaSsaPssSalt();
        if (salt.length > algorithm.getBitLength() / 8) {
            LOGGER.debug("Default PSS salt is too long, truncating");
            salt = Arrays.copyOfRange(salt, 0, algorithm.getBitLength() / 8);
        } else if (salt.length < algorithm.getBitLength() / 8) {
            LOGGER.debug("Default PSS salt is too short, padding");
            byte[] newSalt = new byte[algorithm.getBitLength() / 8];
            System.arraycopy(salt, 0, newSalt, 0, salt.length);
            salt = newSalt;
        }
        calculator.computeRsaPssSignature(
                computations,
                new RsaPrivateKey(privateKey, modulus),
                toBeHasedAndSigned,
                algorithm,
                salt);
    }
}
