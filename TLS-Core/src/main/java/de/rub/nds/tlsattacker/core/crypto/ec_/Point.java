/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec_;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * Can be used to store a point of an elliptic curve.
 *
 * Affine points store their x and y coordinates. The projective z-coordinate
 * (equal to 1) will not be stored. The point at infinity [0:1:0] (the only
 * point with z-coordinate 0) does not store any of it's coordinates.
 */
public class Point implements Serializable {

    /*
     * Point objects are immutable. This should make deep copies in the methods
     * of the EllipticCurve class unnecessary.
     */
    private final FieldElement x;
    private final FieldElement y;
    private final boolean infinity;

    /**
     * Instantiates the point at infinity.
     */
    public Point() {
        this.infinity = true;
        this.x = null;
        this.y = null;
    }

    public static Point createPoint(BigInteger x, BigInteger y, NamedGroup group) {
        EllipticCurve curve = CurveFactory.getCurve(group);
        return curve.getPoint(x, y);
    }

    /**
     * Instantiates an affine point with coordinates x and y. Calling
     * EllipticCurve.getPoint() should always be preferred over using this
     * constructor.
     *
     * @param x
     *            A FieldElement representing the x-coordinate of the point.
     * @param y
     *            A FieldElement representing the y-coordinate of the point. x
     *            and y must be elements of the same field.
     */
    public Point(FieldElement x, FieldElement y) {
        this.x = x;
        this.y = y;
        this.infinity = false;
    }

    /**
     * Returns true if the point is the point at infinity. Returns false if the
     * point is an affine point.
     */
    public boolean isAtInfinity() {
        return this.infinity;
    }

    public FieldElement getX() {
        return this.x;
    }

    public FieldElement getY() {
        return this.y;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        } else {
            Point p = (Point) obj;

            if (this.isAtInfinity() || p.isAtInfinity()) {
                return this.isAtInfinity() == p.isAtInfinity();
            } else {
                return this.x.equals(p.getX()) && this.y.equals(p.getY());
            }
        }
    }

    @Override
    public String toString() {
        if (this.isAtInfinity()) {
            return "Point: Infinity";
        } else {
            return "Point: (" + this.getX().toString() + ", " + this.getY().toString() + ")";
        }
    }
}
