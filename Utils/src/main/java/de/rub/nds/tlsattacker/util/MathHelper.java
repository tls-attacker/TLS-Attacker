/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import java.util.List;

public class MathHelper {

    public static BigInteger intFloorDiv(BigInteger c, BigInteger d) {
        return (c.subtract(c.mod(d))).divide(d);
    }

    public static int intFloorDiv(int c, int d) {
        return (c - (c % d)) / d;
    }

    public static BigInteger intCeilDiv(BigInteger c, BigInteger d) {
        if (c.mod(d).equals(BigInteger.ZERO)) {
            return intFloorDiv(c, d);
        } else {
            return intFloorDiv(c, d).add(BigInteger.ONE);
        }
    }

    public static int intCeilDiv(int c, int d) {
        if ((c % d) == 0) {
            return intFloorDiv(c, d);
        } else {
            return intFloorDiv(c, d) + 1;
        }
    }

    /**
     * @param u The u parameter
     * @param v The v parameter
     * @return (c,r,s) such that c = r u + s v
     */
    public static BigIntegerTriple extendedEuclid(BigInteger u, BigInteger v) {
        BigInteger r = BigInteger.ONE;
        BigInteger s = BigInteger.ZERO;
        BigInteger c = u;
        BigInteger v1 = BigInteger.ZERO;
        BigInteger v2 = BigInteger.ONE;
        BigInteger v3 = v;
        while (!v3.equals(BigInteger.ZERO)) {
            BigInteger q = c.divide(v3);
            BigInteger t1 = r.subtract(q.multiply(v1));
            BigInteger t2 = s.subtract(q.multiply(v2));
            BigInteger t3 = c.subtract(q.multiply(v3));
            r = v1;
            s = v2;
            c = v3;
            v1 = t1;
            v2 = t2;
            v3 = t3;
        }

        return new BigIntegerTriple(c, r, s);
    }

    public static BigInteger gcd(BigInteger u, BigInteger v) {
        return extendedEuclid(u, v).bigA;
    }

    public static BigInteger inverseMod(BigInteger a, BigInteger p) {
        if (!gcd(a, p).equals(BigInteger.ONE)) {
            throw new RuntimeException("does not exist");
        }

        BigInteger b = extendedEuclid(a, p).bigB;
        while (b.compareTo(BigInteger.ZERO) < 0) {
            b = b.add(p);
        }
        return b;
    }

    /**
     * Computes Chinese Reminder Theorem: x == congs[i] mod moduli[i]
     *
     * @param congs A BigInteger[] of congestions
     * @param moduli A BigInteger[] of moduli
     * @return Chinese Reminder Theorem: x == congs[i] mod moduli[i]
     */
    public static BigInteger crt(BigInteger[] congs, BigInteger[] moduli) {

        BigInteger prodModuli = BigInteger.ONE;
        for (BigInteger mod : moduli) {
            prodModuli = prodModuli.multiply(mod);
        }

        BigInteger[] modulus = new BigInteger[moduli.length];
        for (int i = 0; i < moduli.length; i++) {
            modulus[i] = prodModuli.divide(moduli[i]);
        }

        BigInteger retVal = BigInteger.ZERO;
        for (int i = 0; i < moduli.length; i++) {
            // get s value from EEA
            BigInteger tmp = extendedEuclid(moduli[i], modulus[i]).bigC;
            retVal = retVal.add(congs[i].multiply(tmp).multiply(modulus[i]).mod(prodModuli));
        }
        return retVal.mod(prodModuli);
    }

    /**
     * Computes Chinese Reminder Theorem: x == congs[i] mod moduli[i]
     *
     * @param congs A BigInteger[] of congestions
     * @param moduli A BigInteger[] of moduli
     * @return Chinese Reminder Theorem: x == congs[i] mod moduli[i]
     */
    public static BigInteger crt(List<BigInteger> congs, List<BigInteger> moduli) {
        BigInteger[] cs = ArrayConverter.convertListToArray(congs);
        BigInteger[] ms = ArrayConverter.convertListToArray(moduli);
        return crt(cs, ms);
    }

    /**
     * Computes BigInteger sqrt root of a number (floor value). From: <a
     * href="http://stackoverflow.com/questions/4407839/how-can-i-find-the-square-root-of-a-java-biginteger">
     * http://stackoverflow.com/questions/4407839/how-can-i-find-the-square-root-of-a-java-biginteger
     * </a>
     *
     * @param x The x Value
     * @return BigInteger sqrt root of a number
     * @throws IllegalArgumentException If x is negative
     */
    public static BigInteger bigIntSqRootFloor(BigInteger x) throws IllegalArgumentException {
        if (x.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Negative argument.");
        }
        // square roots of 0 and 1 are trivial and
        // y == 0 will cause a divide-by-zero exception
        if (x.equals(BigInteger.ZERO) || x.equals(BigInteger.ONE)) {
            return x;
        } // end if
        BigInteger two = BigInteger.valueOf(2L);
        BigInteger y = x.divide(two);
        // while y>x/y
        while (y.compareTo(x.divide(y)) > 0) {
            // y=(x/y+y)/2
            y = ((x.divide(y)).add(y)).divide(two);
        }
        return y;
    } // end bigIntSqRootFloor

    /**
     * Computes BigInteger sqrt root of a number (ceil value). From: <a
     * href="http://stackoverflow.com/questions/4407839/how-can-i-find-the-square-root-of-a-java-biginteger">
     * http://stackoverflow.com/questions/4407839/how-can-i-find-the-square-root-of-a-java-biginteger</a>
     *
     * @param x The x Value
     * @return BigInteger sqrt root of a number (ceil value)
     * @throws IllegalArgumentException If x is negative
     */
    public static BigInteger bigIntSqRootCeil(BigInteger x) throws IllegalArgumentException {
        if (x.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Negative argument.");
        }
        // square roots of 0 and 1 are trivial and
        // y == 0 will cause a divide-by-zero exception
        if (x.equals(BigInteger.ZERO) || x.equals(BigInteger.ONE)) {
            return x;
        } // end if
        BigInteger two = BigInteger.valueOf(2L);
        BigInteger y = x.divide(two);
        // while y>x/y
        while (y.compareTo(x.divide(y)) > 0) {
            // y=(x/y+y)/2
            y = ((x.divide(y)).add(y)).divide(two);
        }
        if (x.compareTo(y.multiply(y)) == 0) {
            return y;
        } else {
            return y.add(BigInteger.ONE);
        }
    }

    private MathHelper() {}

    public static class BigIntegerTriple {

        private final BigInteger bigA;
        private final BigInteger bigB;
        private final BigInteger bigC;

        public BigIntegerTriple(BigInteger a, BigInteger b, BigInteger c) {
            this.bigA = a;
            this.bigB = b;
            this.bigC = c;
        }

        public BigInteger getBigA() {
            return bigA;
        }

        public BigInteger getBigB() {
            return bigB;
        }

        public BigInteger getBigC() {
            return bigC;
        }
    }
}
