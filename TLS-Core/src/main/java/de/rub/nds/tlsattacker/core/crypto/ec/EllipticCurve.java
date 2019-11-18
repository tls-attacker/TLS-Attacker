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
 * An abstract class that provides functionality for elliptic curve over galois
 * fields.
 */
public abstract class EllipticCurve {
    private Point basePoint;
    private BigInteger basePointOrder;
    /**
     * The modulus of the field over which the curve is defined.
     */
    private final BigInteger modulus;

    /**
     * Every child class must define its own public constructor. These
     * constructors must be able to set the coefficients for the curve. They can
     * use this constructor to set the value of modulus.
     * 
     * @param modulus
     *            The modulus of the field over which the curve is defined.
     */
    protected EllipticCurve(BigInteger modulus) {
        this.modulus = modulus;
    }

    /**
     * Every child class must define its own public constructor. These
     * constructors must be able to set the coefficients for the curve. They can
     * use this constructor to set the values of modulus, basePoint and
     * basePointOrder.
     * 
     * @param modulus
     *            The modulus of the field over which the curve is defined.
     * @param basePointX
     *            The x coordinate of the base point.
     * @param basePointY
     *            The y coordinate of the base point.
     * @param basePointOrder
     *            The order of the base point.
     */
    protected EllipticCurve(BigInteger modulus, BigInteger basePointX, BigInteger basePointY, BigInteger basePointOrder) {
        this.modulus = modulus;
        this.basePoint = this.getPoint(basePointX, basePointY);
        this.basePointOrder = basePointOrder;
    }

    /**
     * Returns the result of p + q on this curve. If one point is null, the
     * result will be null. If one point is not on the curve and the
     * calculations would require dividing by 0, the result will be the point at
     * infinity.
     * 
     * @param p
     *            A point which's coordinates are elements of the field over
     *            which the curve is defined or the point at infinity.
     * @param q
     *            A point which's coordinates are elements of the field over
     *            which the curve is defined or the point at infinity.
     */
    public Point add(Point p, Point q) {

        if (p == null || q == null) {
            return null;
        } else {
            if (p.isAtInfinity()) {
                // O + q == q
                return q;
            }

            if (q.isAtInfinity()) {
                // p + O == p
                return p;
            }

            if (this.inverse(p).equals(q)) {
                // p == -q <=> -p == q
                // => p + q = O
                return new Point();
            }

            return this.additionFormular(p, q);
        }
    }

    /**
     * Returns k*p on this curve. If k or p is null, the result will be null. If
     * the point is not on the curve and the calculations would require dividing
     * by 0, the result will be the point at infinity.
     * 
     * @param p
     *            A point which's coordinates are elements of the field over
     *            which the curve is defined or the point at infinity.
     */
    public Point mult(BigInteger k, Point p) {
        if (k == null || p == null) {
            return null;
        } else {
            if (k.compareTo(BigInteger.ZERO) < 0) {
                k = k.negate();
                p = this.inverse(p);
            }

            // Double-and-add

            Point q = new Point(); // q == O

            for (int i = k.bitLength(); i > 0; i--) {

                q = this.add(q, q);

                if (k.testBit(i - 1)) {
                    q = this.add(q, p);
                }
            }

            return q;
        }
    }

    /**
     * Returns the unique point q with the property p + q = O on this curve. If
     * p is null the result will be null.
     * 
     * @param p
     *            A point which's coordinates are elements of the field over
     *            which the curve is defined or the point at infinity.
     */
    public Point inverse(Point p) {
        if (p == null) {
            return null;
        } else {
            if (p.isAtInfinity()) {
                // -O == O
                return p;
            } else {
                return this.inverseAffine(p);
            }
        }
    }

    /**
     * Returns an affine point with coordinates x and y. The point's coordinates
     * are elements of the field over which this curve is defined. Whenever
     * possible, this method should be used instead of creating a point via its
     * own constructor.
     * 
     * @param x
     *            The x coordinate of the point.
     * @param y
     *            The y coordinate of the point.
     */
    abstract public Point getPoint(BigInteger x, BigInteger y);

    /**
     * Returns true iff the point p is on the curve.
     * 
     * @param p
     *            An affine point which's coordinates are elements of the field
     *            over which the curve is defined or the point at infinity.
     */
    abstract public boolean isOnCurve(Point p);

    /**
     * Returns the unique (affine) point q with the property p + q = O on this
     * curve.
     * 
     * @param p
     *            An affine point which's coordinates are elements of the field
     *            over which the curve is defined.
     */
    abstract protected Point inverseAffine(Point p);

    /**
     * Returns p+q for two affine points p and q, with p != -q. If one point is
     * not on the curve and the calculations would require dividing by 0, the
     * result will be the point at infinity.
     * 
     * @param p
     *            An affine point which's coordinates are elements of the field
     *            over which the curve is defined.
     * @param q
     *            An affine point which's coordinates are elements of the field
     *            over which the curve is defined. Must not be equal to -p.
     */
    abstract protected Point additionFormular(Point p, Point q);

    public Point getBasePoint() {
        return this.basePoint;
    }

    public BigInteger getBasePointOrder() {
        return this.basePointOrder;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public abstract Point createAPointOnCurve(BigInteger x);

    public abstract FieldElement createFieldElement(BigInteger value);

}
