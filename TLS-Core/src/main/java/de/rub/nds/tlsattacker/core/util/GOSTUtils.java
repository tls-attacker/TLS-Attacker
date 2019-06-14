/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public class GOSTUtils {

    private static final Logger LOGGER = LogManager.getLogger(GOSTUtils.class.getName());

    public static byte[] getGostSBox(CipherSuite cipherSuite) {
        return GOST28147Engine.getSBox(cipherSuite.usesGOSTR34112012() ? "Param-Z" : "E-A");
    }

    public static GOST28147ParameterSpec getGostSpec(CipherSuite cipherSuite) {
        return new GOST28147ParameterSpec(getGostSBox(cipherSuite));
    }

    public static BCECGOST3410PrivateKey generate01PrivateKey(GOSTCurve curve, BigInteger s) {
        LOGGER.debug("Generating GOST01 private key for " + curve.name());
        return (BCECGOST3410PrivateKey) generateEcPrivateKey(curve, s, "ECGOST3410");
    }

    public static BCECGOST3410_2012PrivateKey generate12PrivateKey(GOSTCurve curve, BigInteger s) {
        LOGGER.debug("Generating GOST12 private key for " + curve.name());
        return (BCECGOST3410_2012PrivateKey) generateEcPrivateKey(curve, s, "ECGOST3410-2012");
    }

    private static PrivateKey generateEcPrivateKey(GOSTCurve curve, BigInteger s, String keyFactoryAlg) {
        try {
            ECParameterSpec ecParameterSpec = getEcParameterSpec(curve);
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
            return KeyFactory.getInstance(keyFactoryAlg).generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Could not generate GOST private key", e);
            return null;
        }
    }

    public static ECNamedCurveSpec getEcParameterSpec(GOSTCurve curve) {
        String curveName = curve.getJavaName();
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        return new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }
}
