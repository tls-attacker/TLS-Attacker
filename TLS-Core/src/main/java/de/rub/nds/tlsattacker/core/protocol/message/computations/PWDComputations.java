/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.TlsUtils;

public class PWDComputations extends KeyExchangeComputations {

    private EllipticCurve curve;

    /**
     * shared secret derived from the shared password between server and client
     */
    private Point passwordElement;

    /**
     * private secret used to calculate the premaster secret and part of the
     * scalar that gets send to the peer
     */
    private BigInteger privateKeyScalar;

    public static class PWDKeyMaterial {

        public BigInteger privateKeyScalar;
        public BigInteger scalar;
        public Point element;
    }

    @Override
    public void setSecretsInConfig(Config config) {
    }

    public void setCurve(EllipticCurve curve) {
        this.curve = curve;
    }

    public EllipticCurve getCurve() {
        return curve;
    }

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

    /**
     * Computes the password element for TLS_ECCPWD according to RFC 8492
     *
     * @param chooser
     * @param curve
     *            The curve that the generated point should fall on
     * @return
     * @throws CryptoException
     */
    public static Point computePasswordElement(Chooser chooser, EllipticCurve curve) throws CryptoException {
        MacAlgorithm randomFunction = getMacAlgorithm(chooser.getSelectedCipherSuite());

        BigInteger prime = curve.getModulus();

        byte[] base;
        byte[] salt = chooser.getServerPWDSalt();
        if (salt == null && chooser.getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            salt = chooser.getConfig().getDefaultServerPWDSalt();
        }
        if (salt == null) {
            Digest digest = TlsUtils.createHash(HashAlgorithm.sha256);
            base = new byte[digest.getDigestSize()];
            byte[] usernamePW = (chooser.getClientPWDUsername() + chooser.getPWDPassword()).getBytes();
            digest.update(usernamePW, 0, usernamePW.length);
            digest.doFinal(base, 0);
        } else {
            base = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256,
                    (chooser.getClientPWDUsername() + chooser.getPWDPassword()).getBytes(), salt);
        }

        boolean found = false;
        int counter = 0;
        int n = (curve.getModulus().bitLength() + 64) / 8;
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
        } while (!found || counter < chooser.getConfig().getDefaultPWDIterations());

        // use the lsb of the saved seed and Y to determine which of the two
        // possible roots should be used
        int lsbSeed = savedSeed[0] & 1;
        int lsbY = createdPoint.getY().getData().getLowestSetBit() == 0 ? 1 : 0;
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
     * Note that in the RFC, the order of secret and seed is actually switched
     * (the seed is used as the secret in the prf and the context as the
     * seed/message). It is unclear if the author intentionally switched the
     * order of the arguments compared to the TLS RFC or if this is actually
     * intentional.
     *
     * @param chooser
     * @param seed
     * @param context
     * @param outlen
     * @return
     * @throws CryptoException
     */
    protected static byte[] prf(Chooser chooser, byte[] seed, byte[] context, int outlen) throws CryptoException {
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(chooser.getSelectedCipherSuite());
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

            return HKDFunction.expandLabel(hkdfAlgortihm, seed, "TLS-PWD Hunting And Pecking", hashValue, outlen);
        } else {
            PRFAlgorithm prf = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                    chooser.getSelectedCipherSuite());
            return PseudoRandomFunction.compute(prf, seed, "TLS-PWD Hunting And Pecking", context, outlen);
        }
    }

    public static PWDKeyMaterial generateKeyMaterial(EllipticCurve curve, Point passwordElement, Chooser chooser) {
        BigInteger mask;
        PWDKeyMaterial keyMaterial = new PWDKeyMaterial();
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            mask = new BigInteger(1, chooser.getConfig().getDefaultClientPWDMask()).mod(curve.getBasePointOrder());
            keyMaterial.privateKeyScalar = new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate())
                    .mod(curve.getBasePointOrder());
        } else {
            mask = new BigInteger(1, chooser.getConfig().getDefaultServerPWDMask()).mod(curve.getBasePointOrder());
            keyMaterial.privateKeyScalar = new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate())
                    .mod(curve.getBasePointOrder());
        }

        keyMaterial.scalar = mask.add(keyMaterial.privateKeyScalar).mod(curve.getBasePointOrder());

        keyMaterial.element = curve.inverse(curve.mult(mask, passwordElement));
        return keyMaterial;
    }
}
