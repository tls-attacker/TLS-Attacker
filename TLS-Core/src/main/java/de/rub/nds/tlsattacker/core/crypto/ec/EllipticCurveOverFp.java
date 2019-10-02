/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;

/**
 * An elliptic curve over a galois field F_p, where p is a prime number.
 */
public class EllipticCurveOverFp extends EllipticCurve {

    private final FieldElementFp a;
    private final FieldElementFp b;

    /**
     * Instantiates the curve y^2 = x^3 + ax + b over F_p. p must be prime.<br />
     *
     * @param a
     *            The coefficient a in the equation of the curve.
     * @param b
     *            The coefficient b in the equation of the curve.
     * @param p
     *            The prime order of the field over which the curve shall be
     *            defined.
     */
    public EllipticCurveOverFp(BigInteger a, BigInteger b, BigInteger p) {
        super(p);
        this.a = new FieldElementFp(a, this.getModulus());
        this.b = new FieldElementFp(b, this.getModulus());
    }

    /**
     * Instantiates the curve y^2 = x^3 + ax + b over F_p.<br />
     * With base point (x,y) and base point order q. p must be prime.
     *
     * @param a
     *            The coefficient a in the equation of the curve.
     * @param b
     *            The coefficient b in the equation of the curve.
     * @param p
     *            The prime order of the field over which the curve shall be
     *            defined.
     * @param x
     *            The x-coordinate of the base point.
     * @param y
     *            The y-coordinate of the base point.
     * @param q
     *            The order of the base point.
     */
    public EllipticCurveOverFp(BigInteger a, BigInteger b, BigInteger p, BigInteger x, BigInteger y, BigInteger q) {
        super(p, x, y, q);
        this.a = new FieldElementFp(a, this.getModulus());
        this.b = new FieldElementFp(b, this.getModulus());
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
         * If the point's components are not elements of F_p, the point cannot
         * be on the curve. With p being this.getModulus().
         */
        if (p.getX().getClass() != FieldElementFp.class || p.getY().getClass() != FieldElementFp.class) {
            return false;
        }
        FieldElementFp x = (FieldElementFp) p.getX();
        FieldElementFp y = (FieldElementFp) p.getY();
        if (x.getModulus() != this.getModulus() || y.getModulus() != this.getModulus()) {
            return false;
        }

        // Check if y^2 == x^3 + ax + b
        FieldElementFp leftPart = (FieldElementFp) y.mult(y);
        FieldElementFp rightPart = (FieldElementFp) x.mult(x.mult(x)).add(x.mult(this.a)).add(this.b);

        return leftPart.equals(rightPart);
    }

    @Override
    protected Point inverseAffine(Point p) {
        // -p == (x, -y)

        FieldElementFp x = (FieldElementFp) p.getX();
        FieldElementFp yInv = (FieldElementFp) p.getY().addInv();
        return new Point(x, yInv);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        try {
            FieldElementFp x1 = (FieldElementFp) p.getX();
            FieldElementFp y1 = (FieldElementFp) p.getY();
            FieldElementFp x2 = (FieldElementFp) q.getX();
            FieldElementFp y2 = (FieldElementFp) q.getY();

            FieldElementFp lambda;
            if (p.equals(q)) {
                final FieldElementFp two = new FieldElementFp(new BigInteger("2"), this.getModulus());
                final FieldElementFp three = new FieldElementFp(new BigInteger("3"), this.getModulus());

                // lambda := (3*(x1^2) + a) / (2*y1)
                lambda = (FieldElementFp) x1.mult(x1).mult(three).add(this.a).divide(y1.mult(two));
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
            return new Point();
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementFp(value, this.getModulus());
    }

    @Override
    public Point createAPointOnCurve(BigInteger x) {
        BigInteger y = x.pow(3).add(x.multiply(a.getData())).add(b.getData()).mod(getModulus());
        y = y.modPow(getModulus().add(BigInteger.ONE).shiftRight(2), getModulus());
        return getPoint(x, y);
    }
}
