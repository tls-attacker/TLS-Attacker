/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.TlsUtils;

public class PWDComputations extends KeyExchangeComputations {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Computes the password element for TLS_ECCPWD according to RFC 8492
     *
     * @param  chooser
     * @param  curve
     *                         The curve that the generated point should fall on
     * @return
     *
     * @throws CryptoException
     */
    public static Point computePasswordElement(Chooser chooser, EllipticCurve curve) throws CryptoException {
        MacAlgorithm randomFunction = getMacAlgorithm(chooser.getSelectedCipherSuite());

        BigInteger prime = curve.getModulus();

        byte[] base;
        byte[] salt = chooser.getContext().getServerPWDSalt();
        if (salt == null && chooser.getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            salt = chooser.getConfig().getDefaultServerPWDSalt();
        }
        if (salt == null) {
            Digest digest = TlsUtils.createHash(HashAlgorithm.sha256);
            base = new byte[digest.getDigestSize()];
            byte[] usernamePW =
                (chooser.getClientPWDUsername() + chooser.getPWDPassword()).getBytes(StandardCharsets.ISO_8859_1);
            digest.update(usernamePW, 0, usernamePW.length);
            digest.doFinal(base, 0);
        } else {
            base = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256,
                (chooser.getClientPWDUsername() + chooser.getPWDPassword()).getBytes(StandardCharsets.ISO_8859_1),
                salt);
        }

        boolean found = false;
        int counter = 0;
        int n = (curve.getModulus().bitLength() + 64) / Bits.IN_A_BYTE;
        byte[] context;
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            context = chooser.getClientRandom();
        } else {
            context = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        }

        Point createdPoint = null;
        byte[] savedSeed = null;

        do {
            counter++;
            byte[] seedInput = ArrayConverter.concatenate(base, ArrayConverter.intToBytes(counter, 1),
                ArrayConverter.bigIntegerToByteArray(prime));
            byte[] seed = StaticTicketCrypto.generateHMAC(randomFunction, seedInput, new byte[4]);
            byte[] tmp = prf(chooser, seed, context, n);
            BigInteger tmpX = new BigInteger(1, tmp).mod(prime.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            Point tempPoint = curve.createAPointOnCurve(tmpX);

            if (!found && curve.isOnCurve(tempPoint)) {
                createdPoint = tempPoint;
                savedSeed = seed.clone();
                found = true;
                chooser.getContext().getBadSecureRandom().nextBytes(base);
            }
            if (counter > 1000) {
                savedSeed = seed.clone();
                createdPoint = tempPoint;
                LOGGER.warn("Could not find a useful pwd point");
                break;
            }
        } while (!found || counter < chooser.getConfig().getDefaultPWDIterations());

        // use the lsb of the saved seed and Y to determine which of the two
        // possible roots should be used
        int lsbSeed = savedSeed[0] & 1;
        int lsbY = createdPoint.getFieldY().getData().getLowestSetBit() == 0 ? 1 : 0;
        if (lsbSeed == lsbY) {
            createdPoint = curve.inverse(createdPoint);
        }
        return createdPoint;
    }

    protected static MacAlgorithm getMacAlgorithm(CipherSuite suite) {
        if (suite.isSHA256()) {
            return MacAlgorithm.HMAC_SHA256;
        } else if (suite.isSHA384()) {
            return MacAlgorithm.HMAC_SHA384;
        } else if (suite.name().endsWith("SHA")) {
            return MacAlgorithm.HMAC_SHA1;
        } else {
            throw new PreparationException("Unsupported Mac Algorithm for suite " + suite.toString());
        }
    }

    /**
     * Calculates the prf output for the dragonfly password element
     *
     * Note that in the RFC, the order of secret and seed is actually switched (the seed is used as the secret in the
     * prf and the context as the seed/message). It is unclear if the author intentionally switched the order of the
     * arguments compared to the TLS RFC or if this is actually intentional.
     *
     * @param  chooser
     * @param  seed
     * @param  context
     * @param  outlen
     * @return
     *
     * @throws CryptoException
     */
    protected static byte[] prf(Chooser chooser, byte[] seed, byte[] context, int outlen) throws CryptoException {
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(chooser.getSelectedCipherSuite());
            DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite());
            MessageDigest hashFunction = null;
            try {
                hashFunction = MessageDigest.getInstance(digestAlgo.getJavaName());
            } catch (NoSuchAlgorithmException ex) {
                throw new CryptoException("Could not initialize HKDF", ex);
            }
            hashFunction.update(context);
            byte[] hashValue = hashFunction.digest();

            return HKDFunction.expandLabel(hkdfAlgorithm, seed, "TLS-PWD Hunting And Pecking", hashValue, outlen);
        } else {
            PRFAlgorithm prf = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite());
            if (prf != null) {
                return PseudoRandomFunction.compute(prf, seed, "TLS-PWD Hunting And Pecking", context, outlen);
            } else {
                LOGGER.warn("Could not select prf for " + chooser.getSelectedProtocolVersion() + " and "
                    + chooser.getSelectedCipherSuite());
                return new byte[outlen];
            }
        }
    }

    public static PWDKeyMaterial generateKeyMaterial(EllipticCurve curve, Point passwordElement, Chooser chooser) {
        BigInteger mask;
        PWDKeyMaterial keyMaterial = new PWDKeyMaterial();
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            mask = new BigInteger(1, chooser.getConfig().getDefaultClientPWDMask()).mod(curve.getBasePointOrder());
            keyMaterial.privateKeyScalar =
                new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate()).mod(curve.getBasePointOrder());
        } else {
            mask = new BigInteger(1, chooser.getConfig().getDefaultServerPWDMask()).mod(curve.getBasePointOrder());
            keyMaterial.privateKeyScalar =
                new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate()).mod(curve.getBasePointOrder());
        }

        keyMaterial.scalar = mask.add(keyMaterial.privateKeyScalar).mod(curve.getBasePointOrder());

        keyMaterial.element = curve.inverse(curve.mult(mask, passwordElement));
        return keyMaterial;
    }

    /**
     * shared secret derived from the shared password between server and client
     */
    private Point passwordElement;

    /**
     * private secret used to calculate the premaster secret and part of the scalar that gets send to the peer
     */
    private BigInteger privateKeyScalar;

    public Point getPasswordElement() {
        return passwordElement;
    }

    public void setPasswordElement(Point passwordElement) {
        this.passwordElement = passwordElement;
    }

    public BigInteger getPrivateKeyScalar() {
        return privateKeyScalar;
    }

    public void setPrivateKeyScalar(BigInteger privateKeyScalar) {
        this.privateKeyScalar = privateKeyScalar;
    }

    public static class PWDKeyMaterial {

        public BigInteger privateKeyScalar;
        public BigInteger scalar;
        public Point element;
    }
}
