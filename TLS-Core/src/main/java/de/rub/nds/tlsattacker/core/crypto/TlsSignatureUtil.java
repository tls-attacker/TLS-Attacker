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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.protocol.crypto.signature.DsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.EcdsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureVerificationComputations;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.math.BigInteger;

public class TlsSignatureUtil {

    private final SignatureCalculator calculator;

    public TlsSignatureUtil() {
        this.calculator = new SignatureCalculator();
    }

    public void computeSignature(
            Chooser chooser,
            SignatureAndHashAlgorithm algorithm,
            byte[] toBeHasedAndSigned,
            SignatureComputations computations) {
        switch (algorithm.getSignatureAlgorithm()) {
            case DSA:
                if (!(computations instanceof DsaSignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type DsaSignatureComputations for "
                                    + algorithm);
                }
                computeDsaSignature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHasedAndSigned,
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
                        toBeHasedAndSigned,
                        (EcdsaSignatureComputations) computations);
                break;
            case ED25519:
            case ED448:
            case GOSTR34102001:
            case GOSTR34102012_256:
                throw new UnsupportedOperationException(
                        "Not implemented yet: " + algorithm.getSignatureAlgorithm());
            case RSA_PKCS1:
                if (!(computations instanceof EcdsaSignatureComputations)) {
                    throw new IllegalArgumentException(
                            "Computations must be of type RsaPkcs1SignatureComputations for "
                                    + algorithm);
                }
                computeRsaPkcs1Signature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHasedAndSigned,
                        (RsaPkcs1SignatureComputations) computations);
                break;
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
                new EcdsaPrivateKey(privateKey, nonce, NamedEllipticCurveParameters.SECP112R1),
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
}
