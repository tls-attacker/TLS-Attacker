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
import de.rub.nds.protocol.crypto.kem.MlKemCalculator;
import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.protocol.crypto.key.MlKemPrivateKey;
import de.rub.nds.protocol.crypto.key.MlKemPublicKey;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final LoadingCache<Triple<NamedGroup, BigInteger, ECPointFormat>, byte[]>
            publicKeyCache;

    static {
        publicKeyCache =
                CacheBuilder.newBuilder()
                        .maximumSize(256)
                        .expireAfterAccess(10, TimeUnit.MINUTES)
                        .build(CacheLoader.from(KeyShareCalculator::createDhPublicKey));
    }

    public static byte[] createKeyAgreementPublicKey(
            NamedGroup namedGroup, BigInteger privateKey, ECPointFormat pointFormat) {
        // FIXME: remove cache once the crypto implementation is faster
        return publicKeyCache.getUnchecked(Triple.of(namedGroup, privateKey, pointFormat));
    }

    private static byte[] createDhPublicKey(
            Triple<NamedGroup, BigInteger, ECPointFormat> parameters) {
        NamedGroup namedGroup = parameters.getLeft();
        BigInteger privateKey = parameters.getMiddle();
        ECPointFormat pointFormat = parameters.getRight();
        if (namedGroup.isGrease()) {
            return new byte[0];
        }
        if (!namedGroup.isMlKemGroup()) {
            // PQ key encapsulations vary significantly from classic TLS 1.3 public key computations
            // and are hence handled separately
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
                BigInteger publicKey =
                        (BigInteger) group.nTimesGroupOperationOnGenerator(privateKey);
                return DataConverter.bigIntegerToNullPaddedByteArray(
                        publicKey, ((FfdhGroup) group).getParameters().getElementSizeBytes());
            }
        }
        LOGGER.warn("Cannot create Public Key for group {}", namedGroup.name());
        return new byte[0];
    }

    public static byte[] computeDhSharedSecret(
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
     * Creates a post-quantum ML-KEM key share for the client and sets both values in the
     * keyShareEntry
     *
     * @param namedGroup The namedGroup that should be used.
     * @param keyShareEntry The keyShareEntry that should be used.
     * @param random The secure random that should be used.
     */
    public static void createMlKemKeyShare(
            NamedGroup namedGroup, KeyShareEntry keyShareEntry, SecureRandom random) {
        LOGGER.debug("Using group: {}", namedGroup);
        Pair<MlKemPublicKey, MlKemPrivateKey> keyPair =
                MlKemCalculator.generateKeyPair(getMlKemParameters(namedGroup), random);

        keyShareEntry.setMlKemPublicKey(keyPair.getLeft());
        keyShareEntry.setMlKemPrivateKey(keyPair.getRight());
        LOGGER.debug("KeyShare: {}", keyShareEntry.getMlKemPublicKey().getValue());
    }

    /**
     * Creates a post-quantum ML-KEM key share for the client from a fixed decapsulation key and
     * sets both values in the keyShareEntry. The encapsulation key is taken from the decapsulation
     * key, which embeds it. The decapsulation key must have the length defined by the parameter
     * set.
     *
     * @param namedGroup The namedGroup that should be used.
     * @param keyShareEntry The keyShareEntry that should be used.
     * @param decapsulationKey The encoded decapsulation key that should be used.
     */
    public static void createMlKemKeyShare(
            NamedGroup namedGroup, KeyShareEntry keyShareEntry, byte[] decapsulationKey) {
        LOGGER.debug("Using group: {}", namedGroup);
        MlKemParameters parameters = getMlKemParameters(namedGroup);
        MlKemPrivateKey privateKey = new MlKemPrivateKey(parameters, decapsulationKey);

        keyShareEntry.setMlKemPrivateKey(privateKey);
        keyShareEntry.setMlKemPublicKey(
                new MlKemPublicKey(parameters, privateKey.getEncapsulationKey()));
        LOGGER.debug("KeyShare: {}", keyShareEntry.getMlKemPublicKey().getValue());
    }

    /**
     * Computes the shared secret for the ML-KEM algorithms. The client uses the decaps algorithm to
     * retreive the shared secret from the servers share.
     *
     * @param namedGroup The group that should be used.
     * @param privateKey The private key that should be used.
     * @param ciphertext The server's ciphertext that should be decapsulated.
     * @return The computed shared secret.
     */
    public static byte[] mlKemDecaps(
            NamedGroup namedGroup, MlKemPrivateKey privateKey, byte[] ciphertext) {
        LOGGER.debug("Using group: {}", namedGroup);
        return MlKemCalculator.decapsulate(privateKey, ciphertext);
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
    public static MlKemEncapsulation mlKemEncaps(
            NamedGroup namedGroup, byte[] clientPublicKeyBytes, SecureRandom random) {
        return MlKemCalculator.encapsulate(
                getMlKemParameters(namedGroup), clientPublicKeyBytes, random);
    }

    /**
     * Returns the ML-KEM parameter set of the given group, which may either be a pure ML-KEM group
     * or a hybrid group with an ML-KEM component.
     *
     * @param namedGroup The named group that should be used.
     * @return The ML-KEM parameter set of the group.
     */
    public static MlKemParameters getMlKemParameters(NamedGroup namedGroup) {
        return (MlKemParameters) namedGroup.getAnyInvolvedPqGroup().getAsymmetricParameters();
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
