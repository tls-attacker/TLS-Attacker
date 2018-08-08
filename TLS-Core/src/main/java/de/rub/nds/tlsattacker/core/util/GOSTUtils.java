/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public class GOSTUtils {

    private static final Logger LOGGER = LogManager.getLogger(GOSTUtils.class.getName());

    public static BCECGOST3410PrivateKey generate01PrivateKey(String curveName, BigInteger s) {
        return (BCECGOST3410PrivateKey) generateEcPrivateKey(curveName, s, "ECGOST3410");
    }

    public static BCECGOST3410_2012PrivateKey generate12PrivateKey(String curveName, BigInteger s) {
        return (BCECGOST3410_2012PrivateKey) generateEcPrivateKey(curveName, s, "ECGOST3410-2012");
    }

    private static PrivateKey generateEcPrivateKey(String curveName, BigInteger s, String keyFactoryAlg) {
        try {
            ECParameterSpec ecParameterSpec = getEcParameterSpec(curveName);
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
            return KeyFactory.getInstance(keyFactoryAlg).generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Could not generate GOST private key", e);
            return null;
        }
    }

    public static BCECGOST3410PublicKey generate01PublicKey(String curveName, CustomECPoint point) {
        return (BCECGOST3410PublicKey) generateEcPublicKey(curveName, point, "ECGOST3410");
    }

    public static BCECGOST3410_2012PublicKey generate12PublicKey(String curveName, CustomECPoint point) {
        return (BCECGOST3410_2012PublicKey) generateEcPublicKey(curveName, point, "ECGOST3410-2012");
    }

    private static PublicKey generateEcPublicKey(String curveName, CustomECPoint point, String keyFactoryAlg) {
        try {
            ECParameterSpec ecParameterSpec = getEcParameterSpec(curveName);
            ECPoint ecPoint = new ECPoint(point.getX(), point.getY());
            ECPublicKeySpec privateKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            return KeyFactory.getInstance(keyFactoryAlg).generatePublic(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Could not generate GOST public key", e);
            return null;
        }
    }

    public static ECNamedCurveSpec getEcParameterSpec(String curveName) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        return new ECNamedCurveSpec(curveName, spec.getCurve(),
                spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

}
