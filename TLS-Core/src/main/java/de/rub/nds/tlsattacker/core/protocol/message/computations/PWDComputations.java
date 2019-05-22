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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sun.security.ssl.SSLContextImpl;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PWDComputations extends KeyExchangeComputations {

    private ECCurve curve;

    private ECPoint PE;

    private BigInteger priv;

    public static class PWDKeyMaterial {
        public BigInteger priv;
        public BigInteger scalar;
        public ECPoint element;
    }

    @Override
    public void setSecretsInConfig(Config config) {
    }

    public void setCurve(ECCurve curve) {
        this.curve = curve;
    }

    public ECCurve getCurve() {
        return curve;
    }

    public ECPoint getPE() {
        return PE;
    }

    public void setPE(ECPoint PE) {
        this.PE = PE;
    }

    public BigInteger getPrivate() {
        return priv;
    }

    public void setPrivate(BigInteger priv) {
        this.priv = priv;
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
    public static ECPoint computePE(Chooser chooser, ECCurve curve) throws CryptoException {
        MacAlgorithm randomFunction = getMacAlgorithm(chooser.getSelectedCipherSuite());

        BigInteger prime = curve.getField().getCharacteristic();

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
        int n = (curve.getFieldSize() + 64) / 8;
        byte[] context;
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            context = chooser.getClientRandom();
        } else {
            context = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        }

        BigInteger x = null;
        BigInteger y = null;
        byte[] savedSeed = null;

        do {
            counter = counter + 1;
            byte[] seedInput = ArrayConverter.concatenate(base, ArrayConverter.intToBytes(counter, 1),
                    ArrayConverter.bigIntegerToByteArray(prime));
            byte[] seed = StaticTicketCrypto.generateHMAC(randomFunction, seedInput, new byte[4]);
            byte[] tmp = prf(chooser, seed, context, n);
            // (tmp mod (p - 1)) + 1
            BigInteger tmpX = new BigInteger(1, tmp).mod(prime.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            // y^2 = (x^3 + x*val + b) mod p
            BigInteger tmpY = tmpX.pow(3).add(tmpX.multiply(curve.getA().toBigInteger()))
                    .add(curve.getB().toBigInteger()).mod(prime);
            // y^((p-1)/2) mod p to test if y is a quadratic residue
            BigInteger legendre = tmpY.modPow(prime.subtract(BigInteger.ONE).shiftRight(1), prime);
            boolean isQuadraticResidue = legendre.compareTo(BigInteger.ONE) == 0;
            if (isQuadraticResidue && !found) {
                x = tmpX;
                y = tmpY;
                savedSeed = seed.clone();
                found = true;
                chooser.getContext().getBadSecureRandom().nextBytes(base);
            }
        } while (!found || counter < chooser.getConfig().getDefaultPWDIterations());
        // y = y^((p+1)/4) mod p = sqrt(y)
        y = y.modPow(prime.add(BigInteger.ONE).shiftRight(2), prime);
        ECPoint PE = curve.createPoint(x, y);

        // use the lsb of the saved seed and Y to determine which of the two
        // possible roots should be used
        int lsbSeed = savedSeed[0] & 1;
        int lsbY = y.getLowestSetBit() == 0 ? 1 : 0;
        if (lsbSeed == lsbY) {
            PE = PE.negate();
        }
        return PE;
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

    public static PWDKeyMaterial generateKeyMaterial(ECCurve curve, ECPoint PE, Chooser chooser) {
        BigInteger mask;
        PWDKeyMaterial keyMaterial = new PWDKeyMaterial();
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            mask = new BigInteger(1, chooser.getConfig().getDefaultClientPWDMask()).mod(curve.getOrder());
            keyMaterial.priv = new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate())
                    .mod(curve.getOrder());
        } else {
            mask = new BigInteger(1, chooser.getConfig().getDefaultServerPWDMask()).mod(curve.getOrder());
            keyMaterial.priv = new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate())
                    .mod(curve.getOrder());
        }

        keyMaterial.scalar = mask.add(keyMaterial.priv).mod(curve.getOrder());

        keyMaterial.element = PE.multiply(mask).negate().normalize();

        return keyMaterial;
    }
}
