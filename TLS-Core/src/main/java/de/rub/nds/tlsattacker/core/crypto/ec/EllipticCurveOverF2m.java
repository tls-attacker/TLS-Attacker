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
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An elliptic curve over a galois field F_{2^m}.<br />
 * Please notice that the coordinates of affine points are binary polynomials.<br />
 * They are represented by BigIntegers, where the i-th bit represents the i-th coefficient.
 */
public class EllipticCurveOverF2m extends EllipticCurve {

    private static final Logger LOGGER = LogManager.getLogger();

    private final FieldElementF2m curveA;
    private final FieldElementF2m curveB;

    /**
     * Instantiates the curve y^2 + xy = x^3 + ax^2 + b over F_{2^m}.<br />
     *
     * @param a
     *                   A BigInteger representing the binary polynomial a in the equation of the curve.
     * @param b
     *                   A BigInteger representing the binary polynomial b in the equation of the curve.
     * @param polynomial
     *                   A BigInteger representing the binary reduction polynomial that defines the field over which the
     *                   curve is defined.
     */
    public EllipticCurveOverF2m(BigInteger a, BigInteger b, BigInteger polynomial) {
        super(polynomial);
        this.curveA = new FieldElementF2m(a, this.getModulus());
        this.curveB = new FieldElementF2m(b, this.getModulus());
    }

    /**
     * Instantiates the curve y^2 + xy = x^3 + ax^2 + b over F_{2^m}.<br />
     * polynomial is the reduction polynomial of the field.<br />
     * With base point (x, y) and base point order q.
     *
     * @param a
     *                   A BigInteger representing the binary polynomial a in the equation of the curve.
     * @param b
     *                   A BigInteger representing the binary polynomial b in the equation of the curve.
     * @param polynomial
     *                   A BigInteger representing the binary reduction polynomial that defines the field over which the
     *                   curve is defined.
     * @param x
     *                   A BigInteger representing the binary polynomial that represents the x-coordinate of the base
     *                   point.
     * @param y
     *                   A BigInteger representing the binary polynomial that represents the y-coordinate of the base
     *                   point.
     * @param q
     *                   The order of the base point.
     */
    public EllipticCurveOverF2m(BigInteger a, BigInteger b, BigInteger polynomial, BigInteger x, BigInteger y,
        BigInteger q) {
        super(polynomial, x, y, q);
        this.curveA = new FieldElementF2m(a, this.getModulus());
        this.curveB = new FieldElementF2m(b, this.getModulus());
    }

    @Override
    public Point getPoint(BigInteger x, BigInteger y) {
        FieldElementF2m elemX = new FieldElementF2m(x, this.getModulus());
        FieldElementF2m elemY = new FieldElementF2m(y, this.getModulus());

        return new Point(elemX, elemY);
    }

    @Override
    public boolean isOnCurve(Point p) {
        if (p.isAtInfinity()) {
            // The point at infinity is on every curve.
            return true;
        }

        /*
         * If the point's components are not elements of the field over which the curve is defined, the point cannot be
         * on the curve.
         */
        if (p.getFieldX().getClass() != FieldElementF2m.class || p.getFieldY().getClass() != FieldElementF2m.class) {
            return false;
        }
        FieldElementF2m x = (FieldElementF2m) p.getFieldX();
        FieldElementF2m y = (FieldElementF2m) p.getFieldY();
        if (x.getModulus() != this.getModulus() || y.getModulus() != this.getModulus()) {
            return false;
        }

        // Check if y^2 + xy == x^3 + ax^2 + b
        FieldElementF2m leftPart = (FieldElementF2m) y.mult(y).add(x.mult(y));
        FieldElementF2m rightPart =
            (FieldElementF2m) x.mult(x.mult(x)).add(x.mult(x).mult(this.curveA)).add(this.curveB);

        return leftPart.equals(rightPart);
    }

    @Override
    protected Point inverseAffine(Point p) {
        if (!(p.getFieldX() instanceof FieldElementF2m && p.getFieldY() instanceof FieldElementF2m)) {
            LOGGER.warn("Trying to invert non F2m point with F2m curve. Returning point at (0,0)");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
        // -p == (x, x+y)

        FieldElementF2m x = (FieldElementF2m) p.getFieldX();
        FieldElementF2m invY = (FieldElementF2m) p.getFieldY().add(x);

        return new Point(x, invY);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        if (!(p.getFieldX() instanceof FieldElementF2m && p.getFieldY() instanceof FieldElementF2m
            && q.getFieldX() instanceof FieldElementF2m && q.getFieldY() instanceof FieldElementF2m)) {
            LOGGER.warn("Trying to add non F2m points with F2m curve. Returning point at (0,0)");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
        try {
            FieldElementF2m x1 = (FieldElementF2m) p.getFieldX();
            FieldElementF2m y1 = (FieldElementF2m) p.getFieldY();
            FieldElementF2m x2 = (FieldElementF2m) q.getFieldX();
            FieldElementF2m y2 = (FieldElementF2m) q.getFieldY();

            FieldElementF2m x3;
            FieldElementF2m y3;
            FieldElementF2m lambda;

            if (!x1.equals(x2)) {
                // lambda := (y1+y2)/(x1+x2)
                lambda = (FieldElementF2m) y1.add(y2).divide(x1.add(x2));
                // x3 := lambda^2+lambda+x1+x2+a
                x3 = (FieldElementF2m) lambda.mult(lambda).add(lambda).add(x1).add(x2).add(this.curveA);
                // y3 := lambda(x1+x3)+x3+y1
                y3 = (FieldElementF2m) lambda.mult(x1.add(x3)).add(x3).add(y1);
            } else {
                final FieldElementF2m one = new FieldElementF2m(BigInteger.ONE, this.getModulus());

                // lambda := x1+(y1/x1)
                lambda = (FieldElementF2m) x1.add(y1.divide(x1));
                // x3 := lambda^2+lambda+a
                x3 = (FieldElementF2m) lambda.mult(lambda).add(lambda).add(this.curveA);
                // y3 := x1^2+(lambda+1)*x3
                y3 = (FieldElementF2m) x1.mult(x1).add(lambda.add(one).mult(x3));
            }

            return new Point(x3, y3);
        } catch (ArithmeticException e) {
            LOGGER.warn("Encountered an arithmetic exception during addition. Returning point at 0,0");
            return this.getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementF2m(value, this.getModulus());
    }

    /**
     * Returns a point on the curve for the given x coordinate - or the basepoint if such a point does not exist. Of the
     * two possible points, the function always returns the point whose value of z is odd.
     *
     * @param x
     *          The x coordinate of the point
     */
    @Override
    public Point createAPointOnCurve(BigInteger x) {
        FieldElementF2m fieldX = new FieldElementF2m(x, this.getModulus());
        if (x.equals(BigInteger.ZERO)) {
            FieldElementF2m y = curveB.squarePow(this.getModulus().bitLength() - 2);
            return getPoint(x, y.getData());
        } else {
            FieldElementF2m fieldXInverse = (FieldElementF2m) fieldX.multInv();
            FieldElementF2m fieldXInverseSquare = (FieldElementF2m) fieldXInverse.mult(fieldXInverse);
            FieldElementF2m product = (FieldElementF2m) curveB.mult(fieldXInverseSquare);
            FieldElementF2m beta = (FieldElementF2m) fieldX.add(curveA).add(product);
            FieldElementF2m z = (FieldElementF2m) solveQuadraticEquation(beta);
            if (z == null) {
                LOGGER.warn("Was unable to create point on curve - using basepoint instead");
                return this.getBasePoint();
            } else {
                FieldElementF2m y = (FieldElementF2m) fieldX.mult(z);
                Point created = getPoint(x, y.getData());
                if (!z.getData().testBit(0)) {
                    created = inverse(created);
                }
                return created;
            }
        }
    }

    /**
     * Solves z^2 + z = beta using the algorithm D.1.6 of ANSI X9.62
     *
     * @param  beta
     *              An element of F2m
     * @return      The result z for the quadratic equation or null if non-existent
     */
    public FieldElementF2m solveQuadraticEquation(FieldElement beta) {
        if (beta.getData().equals(BigInteger.ZERO)) {
            return new FieldElementF2m(BigInteger.ONE, beta.getModulus());
        }

        FieldElementF2m gamma;
        FieldElementF2m z;
        Random randNum = new Random(0);
        do {
            BigInteger tauData = new BigInteger(32, randNum);
            FieldElementF2m tau = new FieldElementF2m(tauData, beta.getModulus());
            FieldElementF2m w = new FieldElementF2m(beta.getData(), beta.getModulus());
            z = new FieldElementF2m(BigInteger.ZERO, beta.getModulus());

            for (int i = 1; i < (beta.getModulus().bitLength() - 1); i++) {
                z = (FieldElementF2m) z.mult(z).add(w.mult(w).mult(tau));
                w = (FieldElementF2m) w.mult(w).add(beta);
            }

            if (!w.getData().equals(BigInteger.ZERO)) {
                LOGGER.warn("No solution to quadratic equation exists!");
                return null;
            }
            gamma = (FieldElementF2m) z.mult(z).add(z);
        } while (gamma.getData().equals(BigInteger.ZERO));
        return z;
    }
}
