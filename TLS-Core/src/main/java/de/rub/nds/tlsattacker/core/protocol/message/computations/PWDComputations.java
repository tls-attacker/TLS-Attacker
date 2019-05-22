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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

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
        PRFAlgorithm prf = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite());
        BigInteger prime = curve.getField().getCharacteristic();

        byte[] base = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256,
                (chooser.getClientPWDUsername() + chooser.getPWDPassword()).getBytes(), chooser.getServerPWDSalt());
        boolean found = false;
        int counter = 0;
        int n = (curve.getFieldSize() + 64) / 8;
        byte[] context = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());

        BigInteger x = null;
        BigInteger y = null;
        byte[] savedSeed = null;

        do {
            counter = counter + 1;
            byte[] seedInput = ArrayConverter.concatenate(base, ArrayConverter.intToBytes(counter, 1),
                    ArrayConverter.bigIntegerToByteArray(prime));
            byte[] seed = StaticTicketCrypto.generateHMAC(randomFunction, seedInput, new byte[4]);
            byte[] tmp = PseudoRandomFunction.compute(prf, seed, "TLS-PWD Hunting And Pecking", context, n);
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
