/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import de.rub.nds.protocol.crypto.kem.MlKemParameterConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.*;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final LoadingCache<Triple<NamedGroup, BigInteger, ECPointFormat>, byte[]>
            publicKeyCache;

    static {
        publicKeyCache =
                CacheBuilder.newBuilder()
                        .maximumSize(256)
                        .expireAfterAccess(10, TimeUnit.MINUTES)
                        .build(CacheLoader.from(KeyShareCalculator::createPublicKey));
    }

    public static byte[] createPublicKey(
            NamedGroup namedGroup, BigInteger privateKey, ECPointFormat pointFormat) {
        // FIXME: remove cache once the crypto implementation is faster
        return publicKeyCache.getUnchecked(Triple.of(namedGroup, privateKey, pointFormat));
    }

    private static byte[] createPublicKey(
            Triple<NamedGroup, BigInteger, ECPointFormat> parameters) {
        NamedGroup namedGroup = parameters.getLeft();
        BigInteger privateKey = parameters.getMiddle();
        ECPointFormat pointFormat = parameters.getRight();
        if (namedGroup.isGrease()) {
            return new byte[0];
        }
        CyclicGroup<?> group = namedGroup.getGroupParameters().getGroup();

        if (namedGroup.isEcGroup()) {
            if (namedGroup.isShortWeierstrass()) {
                Point publicKey = (Point) group.nTimesGroupOperationOnGenerator(privateKey);
                return PointFormatter.formatToByteArray(
                        namedGroup.getGroupParameters(), publicKey, pointFormat.getFormat());
            } else {
                RFC7748Curve rfcCurve = (RFC7748Curve) group;
                return rfcCurve.computePublicKey(privateKey);
            }
        } else if (namedGroup.isDhGroup()) {
            BigInteger publicKey = (BigInteger) group.nTimesGroupOperationOnGenerator(privateKey);
            return DataConverter.bigIntegerToNullPaddedByteArray(
                    publicKey, ((FfdhGroup) group).getParameters().getElementSizeBytes());
        } else {
            LOGGER.warn("Cannot create Public Key for group {}", namedGroup.name());
            return new byte[0];
        }
    }

    public static byte[] computeSharedSecret(
            NamedGroup group, BigInteger privateKey, byte[] publicKey) {
        if (group.isGrease()) {
            return new byte[0];
        }
        if (group.isDhGroup()) {
            return computeDhSharedSecret(group, privateKey, new BigInteger(1, publicKey));
        } else if (group.isEcGroup()) {
            Point point = PointFormatter.formatFromByteArray(group.getGroupParameters(), publicKey);

            return computeEcSharedSecret(group, privateKey, point);
        } else {
            LOGGER.warn(
                    "Not sure how to compute shared secret for with: {} - using new byte[0] instead.",
                    group.name());
            return new byte[0];
        }
    }

    /**
     * Creates a post-quantum mlkem key share for the client and sets both values in the
     * keyShareEntry
     *
     * @param namedGroup The namedGroup that should be used.
     * @param keyShareEntry The keyShareEntry that should be used.
     * @param random The secure random that should be used.
     */
    public static void createMLKEMKeyShare(
            NamedGroup namedGroup, KeyShareEntry keyShareEntry, SecureRandom random) {
        LOGGER.debug("Using group: {}", namedGroup);
        MLKEMParameters params =
                MlKemParameterConverter.toKemParameters(
                        (MlKemParameters)
                                namedGroup.getAnyInvolvedPqGroup().getAsymmetricParameters());
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(random, params));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) pair.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) pair.getPrivate();

        keyShareEntry.setMLKEMPublicKey(pub);
        keyShareEntry.setMLKEMPrivateKey(priv);
        LOGGER.debug("KeyShare: {}", keyShareEntry.getMLKEMPublicKey().getValue());
    }

    /**
     * Computes the shared secret for the ML-KEM algorithms. The client uses the decaps algorithm to
     * retreive the shared secret from the servers share.
     *
     * @param namedGroup The group that should be used.
     * @param privateKey The private key that should be used.
     * @param publicKey The public key that should be used.
     * @return The computed shared secret.
     */
    public static byte[] mlkemDecaps(
            NamedGroup namedGroup, MLKEMPrivateKeyParameters privateKey, byte[] publicKey) {

        MLKEMExtractor mlkemExtractor = new MLKEMExtractor(privateKey);
        return mlkemExtractor.extractSecret(publicKey);
    }

    /**
     * Computes the encapsulation for the ML-KEM algorithms. The server uses this to generate the
     * ciphertext sent to the client and the shared secret.
     *
     * @param namedGroup The named group that should be used.
     * @param clientPublicKeyBytes The public key that should be used.
     * @param random The secure random that should be used
     * @return The encapsulation result containing both the ciphertext and the shared secret.
     */
    public static SecretWithEncapsulation mlkemEncaps(
            NamedGroup namedGroup, byte[] clientPublicKeyBytes, SecureRandom random) {
        MLKEMParameters mlkemParameters =
                MlKemParameterConverter.toKemParameters(
                        (MlKemParameters)
                                namedGroup.getAnyInvolvedPqGroup().getAsymmetricParameters());
        MLKEMPublicKeyParameters publicKey =
                new MLKEMPublicKeyParameters(mlkemParameters, clientPublicKeyBytes);
        MLKEMGenerator generator = new MLKEMGenerator(random);
        return generator.generateEncapsulated(publicKey);
    }

    /**
     * Computes the shared secret for a DH key exchange. Leading zero bytes of the shared secret are
     * maintained.
     *
     * @param group The group that should be used
     * @param privateKey The private key that should be used
     * @param publicKey The public key that should be used.
     * @return The shared secret with leading zero bytes.
     */
    public static byte[] computeDhSharedSecret(
            NamedGroup group, BigInteger privateKey, BigInteger publicKey) {
        if (!group.isDhGroup()) {
            throw new IllegalArgumentException(
                    "Cannot compute dh shared secret for non ffdhe group");
        }
        CyclicGroup<?> cyclicGroup = group.getGroupParameters().getGroup();
        BigInteger sharedSecret;
        if (cyclicGroup instanceof FfdhGroup) {
            sharedSecret = ((FfdhGroup) cyclicGroup).nTimesGroupOperation(publicKey, privateKey);
        } else {
            throw new IllegalArgumentException(
                    "Cannot compute dh shared secret for non ffdhe group");
        }
        return DataConverter.bigIntegerToNullPaddedByteArray(
                sharedSecret, group.getGroupParameters().getElementSizeBytes());
    }

    /**
     * Computes the shared secret for an ECDH key exchange. Leading zero bytes of the shared secret
     * are maintained.
     *
     * @param namedGroup The group that should be used
     * @param privateKey The private key that should be used
     * @param publicKey The public key that should be used.
     * @return The shared secret with leading zero bytes.
     */
    public static byte[] computeEcSharedSecret(
            NamedGroup namedGroup, BigInteger privateKey, Point publicKey) {
        if (!(namedGroup.getGroupParameters().getGroup() instanceof EllipticCurve)) {
            throw new IllegalArgumentException("Cannot compute ec shared secret for non ec group");
        }
        GroupParameters<?> parameters = namedGroup.getGroupParameters();
        EllipticCurve curve = (EllipticCurve) parameters.getGroup();
        if (curve instanceof RFC7748Curve) {
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;
            return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicKey);
        }

        Point sharedPoint = curve.nTimesGroupOperation(publicKey, privateKey);
        int elementLength = parameters.getElementSizeBytes();
        return DataConverter.bigIntegerToNullPaddedByteArray(
                sharedPoint.getFieldX().getData(), elementLength);
    }
}
