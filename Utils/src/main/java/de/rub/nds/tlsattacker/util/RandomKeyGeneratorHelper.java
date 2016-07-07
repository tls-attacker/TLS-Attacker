/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.security.SecureRandom;
import java.util.Random;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RandomKeyGeneratorHelper
{

    public static ECPublicKeyParameters generateECPublicKeyParameters()
    {
        //Should we also generate random curves?
        X9ECParameters ecp = SECNamedCurves.getByName(getRandomCurveName());
        ECKeyPairGenerator keygen = new ECKeyPairGenerator();
        ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(),ecp.getG(), ecp.getN(), ecp.getH(),ecp.getSeed());
        keygen.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        return (ECPublicKeyParameters)keygen.generateKeyPair().getPublic();
    }

    private static String getRandomCurveName()
    {
        String curveName = null;
        Random r = new Random();
        do
        {
            switch (r.nextInt(33))
            {
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
        }
        while (curveName != null);
        return curveName; 
   }
}
