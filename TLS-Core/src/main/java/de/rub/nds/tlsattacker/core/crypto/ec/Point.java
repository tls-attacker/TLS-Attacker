/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Can be used to store a point of an elliptic curve.
 *
 * Affine points store their x and y coordinates. The projective z-coordinate
 * (equal to 1) will not be stored. The point at infinity [0:1:0] (the only
 * point with z-coordinate 0) does not store any of it's coordinates.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Point implements Serializable {

    /*
     * Point objects are immutable. This should make deep copies in the methods
     * of the EllipticCurve class unnecessary.
     */
    @XmlElements(value = { @XmlElement(type = FieldElementF2m.class, name = "xFieldElementF2m"),
            @XmlElement(type = FieldElementFp.class, name = "xFieldElementFp") })
    private final FieldElement x;
    @XmlElements(value = { @XmlElement(type = FieldElementF2m.class, name = "yFieldElementF2m"),
            @XmlElement(type = FieldElementFp.class, name = "yFieldElementFp") })
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

    public static Point createPoint(BigInteger x, BigInteger y, GOSTCurve group) {
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
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.x);
        hash = 89 * hash + Objects.hashCode(this.y);
        hash = 89 * hash + (this.infinity ? 1 : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Point other = (Point) obj;
        if (this.infinity != other.infinity) {
            return false;
        }
        if (!Objects.equals(this.x, other.x)) {
            return false;
        }
        if (!Objects.equals(this.y, other.y)) {
            return false;
        }
        return true;
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
