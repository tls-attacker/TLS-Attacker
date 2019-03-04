/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.math.BigInteger;
import java.util.Random;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

public class RandomKeyGeneratorHelper {

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static AsymmetricCipherKeyPair dhPair = null;

    public static AsymmetricCipherKeyPair generateECPublicKey() {

        // Should we also generate random curves?
        X9ECParameters ecp = SECNamedCurves.getByName(getRandomCurveName());
        ECKeyPairGenerator keygen = new ECKeyPairGenerator();
        ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
                ecp.getSeed());
        keygen.init(new ECKeyGenerationParameters(domainParams, RandomHelper.getBadSecureRandom()));
        return keygen.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair generateDHPublicKey() {
        // DH generation takes a lot of the time of the fuzzer, we cache one and
        // reuse it for now
        if (dhPair == null) {
            // TODO generate better keys
            Random r = RandomHelper.getRandom();

            BigInteger valP = new BigInteger(r.nextInt(4100), r);
            BigInteger valG = new BigInteger(r.nextInt(4100), r);
            DHParameters dhp = null;
            BigInteger x = null;
            BigInteger y = null;
            try {
                dhp = new DHParameters(valP, valG);
                x = calculatePrivate(dhp);
                y = calculatePublic(dhp, x);
            } catch (java.lang.IllegalArgumentException E) {
                // java.lang.IllegalArgumentException: 'min' may not be greater
                // than
                // 'max'
                // at
                // org.bouncycastle.util.BigIntegers.createRandomInRange(Unknown
                // Source)
                try {
                    BigInteger swap = valP;
                    valP = valG;
                    valG = swap;
                    dhp = new DHParameters(valP, valG);
                    x = calculatePrivate(dhp);
                    y = calculatePublic(dhp, x);
                } catch (java.lang.IllegalArgumentException Ex) {
                    // Okay we gave our best these parameters are not viable try
                    // complete new ones
                    dhPair = generateDHPublicKey();
                }
            }
            dhPair = new AsymmetricCipherKeyPair(new DHPublicKeyParameters(y, dhp), new DHPrivateKeyParameters(x, dhp));
        }
        return dhPair;
    }

    private static BigInteger calculatePrivate(DHParameters dhParams) {
        int limit = dhParams.getL();

        if (limit != 0) {
            int minWeight = limit >>> 2;
            for (;;) {
                BigInteger x = new BigInteger(limit, new BadRandom()).setBit(limit - 1);
                if (WNafUtil.getNafWeight(x) >= minWeight) {
                    return x;
                }
            }
        }

        BigInteger min = TWO;
        int m = dhParams.getM();
        if (m != 0) {
            min = ONE.shiftLeft(m - 1);
        }

        BigInteger q = dhParams.getQ();
        if (q == null) {
            q = dhParams.getP();
        }
        BigInteger max = q.subtract(TWO);

        int minWeight = max.bitLength() >>> 2;
        for (;;) {
            BigInteger x = BigIntegers.createRandomInRange(min, max, new BadRandom());
            if (WNafUtil.getNafWeight(x) >= minWeight) {
                return x;
            }
        }
    }

    private static BigInteger calculatePublic(DHParameters dhParams, BigInteger x) {
        return dhParams.getG().modPow(x, dhParams.getP());
    }

    private static String getRandomCurveName() {
        String curveName = null;
        Random r = new Random();
        do {
            switch (r.nextInt(33)) {
                case 0:
                    curveName = "secp112r1";
                    break;
                case 1:
                    curveName = "secp112r2";
                    break;
                case 2:
                    curveName = "secp128r1";
                    break;
                case 3:
                    curveName = "secp128r2";
                    break;
                case 4:
                    curveName = "secp160k1";
                    break;
                case 5:
                    curveName = "secp160r1";
                    break;
                case 6:
                    curveName = "secp160r2";
                    break;
                case 7:
                    curveName = "secp192k1";
                    break;
                case 8:
                    curveName = "secp192r1";
                    break;
                case 9:
                    curveName = "secp224k1";
                    break;
                case 10:
                    curveName = "secp224r1";
                    break;
                case 11:
                    curveName = "secp256k1";
                    break;
                case 12:
                    curveName = "secp256r1";
                    break;
                case 13:
                    curveName = "secp384r1";
                    break;
                case 14:
                    curveName = "secp521r1";
                    break;
                case 15:
                    curveName = "sect113r1";
                    break;
                case 16:
                    curveName = "sect113r2";
                    break;
                case 17:
                    curveName = "sect131r1";
                    break;
                case 18:
                    curveName = "sect131r2";
                    break;
                case 19:
                    curveName = "sect163k1";
                    break;
                case 20:
                    curveName = "sect163r1";
                    break;
                case 21:
                    curveName = "sect163r2";
                    break;
                case 22:
                    curveName = "sect193r1";
                    break;
                case 23:
                    curveName = "sect193r2";
                    break;
                case 24:
                    curveName = "sect233k1";
                    break;
                case 25:
                    curveName = "sect233r1";
                    break;
                case 26:
                    curveName = "sect239k1";
                    break;
                case 27:
                    curveName = "sect283k1";
                    break;
                case 28:
                    curveName = "sect283r1";
                    break;
                case 29:
                    curveName = "sect409k1";
                    break;
                case 30:
                    curveName = "sect409r1";
                    break;
                case 31:
                    curveName = "sect571k1";
                    break;
                case 32:
                    curveName = "sect571r1";
                    break;

            }
        } while (curveName == null);
        return curveName;
    }

    private RandomKeyGeneratorHelper() {
    }

}
