/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class EcPemCreator {

    static final String BEGIN_EC_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n";
    static final String END_EC_PRIVATE_KEY = "-----END EC PRIVATE KEY-----\n";

    private EcPemCreator() {

    }

    public static String createPemFromPrivateEcKey(String namedCurve, BigInteger secret)
            throws InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException,
            NoSuchProviderException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
        parameters.init(new ECGenParameterSpec(namedCurve));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPrivateKeySpec privKey = new ECPrivateKeySpec(secret, ecParameters);
        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(privKey);
        String pem = BEGIN_EC_PRIVATE_KEY + DatatypeConverter.printBase64Binary(privateKey.getEncoded())
                + "\n-----END EC PRIVATE KEY-----\n";
        return pem;
    }

}
