/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec.oracles;

import de.rub.nds.tlsattacker.tls.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.tls.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.tls.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import javax.crypto.KeyAgreement;

/**
 * This class is here only to test some results from our invalid curve paper,
 * the oracle should not work anymore because the SUN implementation has been
 * patched.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestECSunOracle extends ECOracle {

    private final ECComputer computer;

    public TestECSunOracle(String namedCurve) {
        curve = CurveFactory.getNamedCurve(namedCurve);
        BigInteger privateKey = new BigInteger(curve.getKeyBits() - 20, new Random());
        // BigInteger privateKey = new
        // BigInteger("25091756309879652045519159642875354611257005804552159157");
        computer = new ECComputer(curve, privateKey);
        LOGGER.debug("Using the following key: " + privateKey);
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret) {
        numberOfQueries++;
        if (numberOfQueries % 100 == 0) {
            LOGGER.debug("Number of queries so far: {}", numberOfQueries);
        }
        BigInteger result;
        try {
            result = computeSecretWithSunAlgorithm(computer.getCurve().getName(), ecPoint.getX(), ecPoint.getY(),
                    computer.getSecret());
            BigInteger test = computer.mul(ecPoint).getX();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidKeyException | DivisionException ex) {
            result = null;
            // TODO ugly
        }

        if (result == null) {
            return false;
        } else {
            return (result.compareTo(guessedSecret) == 0);
        }
    }

    public ECComputer getComputer() {
        return computer;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        return guessedSecret.equals(computer.getSecret());
    }

    private BigInteger computeSecretWithSunAlgorithm(String namedCurve, BigInteger badX, BigInteger badY,
            BigInteger secret) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException {
        // initialize java stuff
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec(namedCurve);
        kpg.initialize(ecsp);

        // decryption key
        KeyPair kpU = kpg.genKeyPair();
        ECPublicKey ecPubKeyU = (ECPublicKey) kpU.getPublic();

        ECPublicKeySpec bpubs = new ECPublicKeySpec(new ECPoint(badX, badY), ecPubKeyU.getParams());
        ECPrivateKeySpec bprivs = new ECPrivateKeySpec(secret, ecPubKeyU.getParams());

        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");

        KeyFactory kfa = KeyFactory.getInstance("EC");
        ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
        ECPrivateKey bpriv = (ECPrivateKey) kfa.generatePrivate(bprivs);

        ecdhV.init(bpriv);
        try {
            ecdhV.doPhase(bpub, true);
            return new BigInteger(1, ecdhV.generateSecret());
        } catch (InvalidKeyException | IllegalStateException e) {
            return null;
        }
    }
}
