/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.ANONYMOUS;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.DSA;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.ECDSA;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.ED25519;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.ED448;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.GOSTR34102001;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.GOSTR34102012_256;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.GOSTR34102012_512;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.RSA;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.RSA_PSS_PSS;
import static de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm.RSA_PSS_RSAE;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.signature.DsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.EcdsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.EdwardsSignatureComputations;
import de.rub.nds.protocol.crypto.signature.GostSignatureComputations;
import de.rub.nds.protocol.crypto.signature.NoSignatureComputations;
import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.protocol.crypto.signature.RsaPssSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureVerificationComputations;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
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
            case ANONYMOUS:
            case DSA:
                computeDsaSignature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHasedAndSigned,
                        (EcdsaSignatureComputations) computations);
                break;
            case ECDSA:
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
            case GOSTR34102012_512:
            case RSA:
                computeRsaPkcs1Signature(
                        chooser,
                        algorithm.getHashAlgorithm(),
                        toBeHasedAndSigned,
                        (RsaPkcs1SignatureComputations) computations);
                break;
            case RSA_PSS_PSS:
            case RSA_PSS_RSAE:
        }
    }

    public void verifySignature(
            Chooser chooser,
            SignatureAndHashAlgorithm algorithm,
            byte[] signature,
            byte[] toBeSigned,
            SignatureVerificationComputations computations) {
        switch (algorithm.getSignatureAlgorithm()) {
            case ANONYMOUS:
            case DSA:
            case ECDSA:
            case ED25519:
            case ED448:
            case GOSTR34102001:
            case GOSTR34102012_256:
            case GOSTR34102012_512:
            case RSA:
            case RSA_PSS_PSS:
            case RSA_PSS_RSAE:
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
                privateKey,
                toBeHasedAndSigned,
                nonce,
                NamedEllipticCurveParameters.SECP112R1,
                algorithm);
    }

    private void computeDsaSignature(
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
                        .getSubjectDsaPrivateKey();
        nonce = chooser.getConfig().getDefaultEcdsaNonce();
        calculator.computeEcdsaSignature(
                computations,
                privateKey,
                toBeHasedAndSigned,
                nonce,
                NamedEllipticCurveParameters.SECP112R1,
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
                computations, privateKey, modulus, toBeHasedAndSigned, algorithm);
    }

    public SignatureComputations createSignatureComputations(
            SignatureAlgorithm signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case ANONYMOUS:
                return new NoSignatureComputations();
            case DSA:
                return new DsaSignatureComputations();
            case ECDSA:
                return new EcdsaSignatureComputations();
            case ED25519:
            case ED448:
                return new EdwardsSignatureComputations();
            case GOSTR34102001:
            case GOSTR34102012_256:
            case GOSTR34102012_512:
                return new GostSignatureComputations();
            case RSA:
                return new RsaPkcs1SignatureComputations();
            case RSA_PSS_PSS:
            case RSA_PSS_RSAE:
                return new RsaPssSignatureComputations();
            default:
                throw new UnsupportedOperationException(
                        "Unsupported signature algorithm: " + signatureAlgorithm);
        }
    }
}
