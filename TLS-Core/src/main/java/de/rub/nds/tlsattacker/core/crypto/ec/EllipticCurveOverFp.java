/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An elliptic curve over a galois field F_p, where p is a prime number.
 */
public class EllipticCurveOverFp extends EllipticCurve {

    private static final Logger LOGGER = LogManager.getLogger();

    private final FieldElementFp fieldA;
    private final FieldElementFp fieldB;

    /**
     * Instantiates the curve y^2 = x^3 + ax + b over F_p. p must be prime.<br />
     *
     * @param a
     *          The coefficient a in the equation of the curve.
     * @param b
     *          The coefficient b in the equation of the curve.
     * @param p
     *          The prime order of the field over which the curve shall be defined.
     */
    public EllipticCurveOverFp(BigInteger a, BigInteger b, BigInteger p) {
        super(p);
        this.fieldA = new FieldElementFp(a, this.getModulus());
        this.fieldB = new FieldElementFp(b, this.getModulus());
    }

    /**
     * Instantiates the curve y^2 = x^3 + ax + b over F_p.<br />
     * With base point (x,y) and base point order q. p must be prime.
     *
     * @param a
     *          The coefficient a in the equation of the curve.
     * @param b
     *          The coefficient b in the equation of the curve.
     * @param p
     *          The prime order of the field over which the curve shall be defined.
     * @param x
     *          The x-coordinate of the base point.
     * @param y
     *          The y-coordinate of the base point.
     * @param q
     *          The order of the base point.
     */
    public EllipticCurveOverFp(BigInteger a, BigInteger b, BigInteger p, BigInteger x, BigInteger y, BigInteger q) {
        super(p, x, y, q);
        this.fieldA = new FieldElementFp(a, this.getModulus());
        this.fieldB = new FieldElementFp(b, this.getModulus());
    }

    @Override
    public Point getPoint(BigInteger x, BigInteger y) {
        FieldElementFp elemX = new FieldElementFp(x, this.getModulus());
        FieldElementFp elemY = new FieldElementFp(y, this.getModulus());

        return new Point(elemX, elemY);
    }

    @Override
    public boolean isOnCurve(Point p) {
        if (p.isAtInfinity()) {
            // The point at infinity is on every curve.
            return true;
        }

        /*
         * If the point's components are not elements of F_p, the point cannot be on the curve. With p being
         * this.getModulus().
         */
        if (p.getFieldX().getClass() != FieldElementFp.class || p.getFieldY().getClass() != FieldElementFp.class) {
            return false;
        }
        FieldElementFp x = (FieldElementFp) p.getFieldX();
        FieldElementFp y = (FieldElementFp) p.getFieldY();
        if (x.getModulus() != this.getModulus() || y.getModulus() != this.getModulus()) {
            return false;
        }

        // Check if y^2 == x^3 + ax + b
        FieldElementFp leftPart = (FieldElementFp) y.mult(y);
        FieldElementFp rightPart =
            (FieldElementFp) x.mult(x.mult(x)).add(x.mult(this.getFieldA())).add(this.getFieldB());

        return leftPart.equals(rightPart);
    }

    @Override
    protected Point inverseAffine(Point p) {
        // -p == (x, -y)
        if (!(p.getFieldX() instanceof FieldElementFp && p.getFieldY() instanceof FieldElementFp)) {
            LOGGER.warn("Trying to invert non Fp point with Fp curve. Returning point at (0,0)");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
        FieldElementFp x = (FieldElementFp) p.getFieldX();
        FieldElementFp invY = (FieldElementFp) p.getFieldY().addInv();
        return new Point(x, invY);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        if (!(p.getFieldX() instanceof FieldElementFp && p.getFieldY() instanceof FieldElementFp
            && q.getFieldX() instanceof FieldElementFp && q.getFieldY() instanceof FieldElementFp)) {
            LOGGER.warn("Trying to add non Fp points with Fp curve. Returning point at (0,0)");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
        try {
            FieldElementFp x1 = (FieldElementFp) p.getFieldX();
            FieldElementFp y1 = (FieldElementFp) p.getFieldY();
            FieldElementFp x2 = (FieldElementFp) q.getFieldX();
            FieldElementFp y2 = (FieldElementFp) q.getFieldY();

            FieldElementFp lambda;
            if (p.equals(q)) {
                final FieldElementFp two = new FieldElementFp(new BigInteger("2"), this.getModulus());
                final FieldElementFp three = new FieldElementFp(new BigInteger("3"), this.getModulus());

                // lambda := (3*(x1^2) + a) / (2*y1)
                lambda = (FieldElementFp) x1.mult(x1).mult(three).add(this.getFieldA()).divide(y1.mult(two));
            } else {
                // lambda := (y2 - y1) / (x2 - x1)
                lambda = (FieldElementFp) y2.subtract(y1).divide(x2.subtract(x1));
            }

            FieldElementFp lambdaSq = (FieldElementFp) lambda.mult(lambda);

            // x3 = lambda^2 - x1 - x2
            FieldElementFp x3 = (FieldElementFp) lambdaSq.subtract(x1).subtract(x2);
            // y3 = lambda*(x1 - x3) - y1
            FieldElementFp y3 = (FieldElementFp) lambda.mult(x1.subtract(x3)).subtract(y1);

            return new Point(x3, y3);
        } catch (ArithmeticException e) {
            LOGGER.warn("Encountered an arithmetic exception during addition. Returning point at 0,0");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementFp(value, this.getModulus());
    }

    /**
     * Returns a point on the curve for the given x coordinate - or the basepoint if such a point does not exist. Of the
     * two possible points, the function always returns the point whose y coordinate is odd.
     */
    @Override
    public Point createAPointOnCurve(BigInteger x) {
        BigInteger y = x.pow(3).add(x.multiply(getFieldA().getData())).add(getFieldB().getData()).mod(getModulus());
        y = modSqrt(y, getModulus());
        if (y == null) {
            LOGGER.warn("Was unable to create point on curve - using basepoint instead");
            return this.getBasePoint();
        } else {
            Point created = getPoint(x, y);
            if (!y.testBit(0)) {
                created = inverse(created);
            }
            return created;
        }
    }

    /**
     * @return the a
     */
    public FieldElementFp getFieldA() {
        return fieldA;
    }

    /**
     * @return the b
     */
    public FieldElementFp getFieldB() {
        return fieldB;
    }

    private int legendreSymbol(BigInteger a, BigInteger p) {
        BigInteger ls = a.modPow(p.subtract(BigInteger.ONE).divide(new BigInteger("2")), p);
        if (ls.compareTo(p.subtract(BigInteger.ONE)) == 0) {
            return -1;
        } else {
            return ls.intValue();
        }
    }

    public BigInteger modSqrt(BigInteger a, BigInteger p) {
        if (legendreSymbol(a, p) != 1 || a.compareTo(BigInteger.ZERO) == 0 || a.compareTo(new BigInteger("2")) == 0) {
            // no solution exists
            return null;
        } else {
            if (p.mod(new BigInteger("4")).compareTo(new BigInteger("3")) == 0) {
                // faster method for this case
                return a.modPow(p.add(BigInteger.ONE).divide(new BigInteger("4")), p);
            } else {
                // Tonelli Shanks
                BigInteger r = p.subtract(BigInteger.ONE);
                BigInteger e = BigInteger.ZERO;

                while (r.mod(new BigInteger("2")).compareTo(BigInteger.ZERO) == 0) {
                    r = r.divide(new BigInteger("2"));
                    e = e.add(BigInteger.ONE);
                }

                // find n with (n|p) = -1
                BigInteger n = new BigInteger("2");
                while (legendreSymbol(n, p) != -1) {
                    n = n.add(BigInteger.ONE);
                }

                BigInteger z = n.modPow(r, p);
                BigInteger y = z;
                BigInteger s = e;
                BigInteger x = a.modPow(r.subtract(BigInteger.ONE).divide(new BigInteger("2")), p);

                BigInteger b = a.multiply(x.pow(2)).mod(p);
                x = a.multiply(x).mod(p);
                while (b.mod(p).compareTo(BigInteger.ONE) != 0) {
                    BigInteger m = BigInteger.ONE;
                    while (b.modPow(new BigInteger("2").pow(m.intValue()), p).compareTo(BigInteger.ONE) != 0) {
                        m = m.add(BigInteger.ONE);
                    }

                    BigInteger t = y.modPow(new BigInteger("2").pow(s.intValue() - m.intValue() - 1), p);
                    y = t.pow(2).mod(p);
                    s = m;

                    x = t.multiply(x).mod(p);
                    b = y.multiply(b).mod(p);

                }

                return x;
            }
        }
    }
}
