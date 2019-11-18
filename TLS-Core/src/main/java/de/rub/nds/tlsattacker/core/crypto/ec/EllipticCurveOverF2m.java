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
 * An elliptic curve over a galois field F_{2^m}.<br />
 * Please notice that the coordinates of affine points are binary polynomials.<br />
 * They are represented by BigIntegers, where the i-th bit represents the i-th
 * coefficient.
 */
public class EllipticCurveOverF2m extends EllipticCurve {

    private final FieldElementF2m a;
    private final FieldElementF2m b;

    /**
     * Instantiates the curve y^2 + xy = x^3 + ax^2 + b over F_{2^m}.<br />
     *
     * @param a
     *            A BigInteger representing the binary polynomial a in the
     *            equation of the curve.
     * @param b
     *            A BigInteger representing the binary polynomial b in the
     *            equation of the curve.
     * @param polynomial
     *            A BigInteger representing the binary reduction polynomial that
     *            defines the field over which the curve is defined.
     */
    public EllipticCurveOverF2m(BigInteger a, BigInteger b, BigInteger polynomial) {
        super(polynomial);
        this.a = new FieldElementF2m(a, this.getModulus());
        this.b = new FieldElementF2m(b, this.getModulus());
    }

    /**
     * Instantiates the curve y^2 + xy = x^3 + ax^2 + b over F_{2^m}.<br />
     * polynomial is the reduction polynomial of the field.<br />
     * With base point (x, y) and base point order q.
     *
     * @param a
     *            A BigInteger representing the binary polynomial a in the
     *            equation of the curve.
     * @param b
     *            A BigInteger representing the binary polynomial b in the
     *            equation of the curve.
     * @param polynomial
     *            A BigInteger representing the binary reduction polynomial that
     *            defines the field over which the curve is defined.
     * @param x
     *            A BigInteger representing the binary polynomial that
     *            represents the x-coordinate of the base point.
     * @param y
     *            A BigInteger representing the binary polynomial that
     *            represents the y-coordinate of the base point.
     * @param q
     *            The order of the base point.
     */
    public EllipticCurveOverF2m(BigInteger a, BigInteger b, BigInteger polynomial, BigInteger x, BigInteger y,
            BigInteger q) {
        super(polynomial, x, y, q);
        this.a = new FieldElementF2m(a, this.getModulus());
        this.b = new FieldElementF2m(b, this.getModulus());
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
         * If the point's components are not elements of the field over which
         * the curve is defined, the point cannot be on the curve.
         */
        if (p.getX().getClass() != FieldElementF2m.class || p.getY().getClass() != FieldElementF2m.class) {
            return false;
        }
        FieldElementF2m x = (FieldElementF2m) p.getX();
        FieldElementF2m y = (FieldElementF2m) p.getY();
        if (x.getModulus() != this.getModulus() || y.getModulus() != this.getModulus()) {
            return false;
        }

        // Check if y^2 + xy == x^3 + ax^2 + b
        FieldElementF2m leftPart = (FieldElementF2m) y.mult(y).add(x.mult(y));
        FieldElementF2m rightPart = (FieldElementF2m) x.mult(x.mult(x)).add(x.mult(x).mult(this.a)).add(this.b);

        return leftPart.equals(rightPart);
    }

    @Override
    protected Point inverseAffine(Point p) {
        // -p == (x, x+y)

        FieldElementF2m x = (FieldElementF2m) p.getX();
        FieldElementF2m invY = (FieldElementF2m) p.getY().add(x);

        return new Point(x, invY);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        try {
            FieldElementF2m x1 = (FieldElementF2m) p.getX();
            FieldElementF2m y1 = (FieldElementF2m) p.getY();
            FieldElementF2m x2 = (FieldElementF2m) q.getX();
            FieldElementF2m y2 = (FieldElementF2m) q.getY();

            FieldElementF2m x3;
            FieldElementF2m y3;
            FieldElementF2m lambda;

            if (!x1.equals(x2)) {
                // lambda := (y1+y2)/(x1+x2)
                lambda = (FieldElementF2m) y1.add(y2).divide(x1.add(x2));
                // x3 := lambda^2+lambda+x1+x2+a
                x3 = (FieldElementF2m) lambda.mult(lambda).add(lambda).add(x1).add(x2).add(this.a);
                // y3 := lambda(x1+x3)+x3+y1
                y3 = (FieldElementF2m) lambda.mult(x1.add(x3)).add(x3).add(y1);
            } else {
                final FieldElementF2m one = new FieldElementF2m(BigInteger.ONE, this.getModulus());

                // lambda := x1+(y1/x1)
                lambda = (FieldElementF2m) x1.add(y1.divide(x1));
                // x3 := lambda^2+lambda+a
                x3 = (FieldElementF2m) lambda.mult(lambda).add(lambda).add(this.a);
                // y3 := x1^2+(lambda+1)*x3
                y3 = (FieldElementF2m) x1.mult(x1).add(lambda.add(one).mult(x3));
            }

            return new Point(x3, y3);
        } catch (ArithmeticException e) {
            return new Point();
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementF2m(value, this.getModulus());
    }

    @Override
    public Point createAPointOnCurve(BigInteger x) {
        throw new UnsupportedOperationException("Currently not supported");
    }
}
