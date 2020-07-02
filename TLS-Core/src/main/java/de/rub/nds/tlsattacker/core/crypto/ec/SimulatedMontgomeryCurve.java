/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;

/**
 * A Montgomery Curve that internally uses a Weierstrass Curve
 */
public class SimulatedMontgomeryCurve extends EllipticCurveOverFp {

    private final EllipticCurveOverFp weierstrassEquivalent;

    public SimulatedMontgomeryCurve(BigInteger a, BigInteger b, BigInteger modulus, BigInteger basePointX,
            BigInteger basePointY, BigInteger basePointOrder) {
        super(a, b, modulus, basePointX, basePointY, basePointOrder);
        weierstrassEquivalent = computeWeierstrassEquivalent();
    }

    @Override
    public Point getPoint(BigInteger x, BigInteger y) {
        FieldElementFp elemX = new FieldElementFp(x, this.getModulus());
        FieldElementFp elemY = new FieldElementFp(y, this.getModulus());

        return new Point(elemX, elemY);
    }

    @Override
    public boolean isOnCurve(Point p) {
        Point wP = toWeierstrass(p);
        return getWeierstrassEquivalent().isOnCurve(wP);
    }

    @Override
    protected Point inverseAffine(Point p) {
        Point wP = toWeierstrass(p);
        Point wRes = getWeierstrassEquivalent().inverseAffine(wP);
        return toMontgomery(wRes);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        Point wP = toWeierstrass(p);
        Point wQ = toWeierstrass(q);
        Point wRes = getWeierstrassEquivalent().additionFormular(wP, wQ);
        return toMontgomery(wRes);
    }

    @Override
    public Point createAPointOnCurve(BigInteger x) {
        BigInteger val = x.pow(3).add(x.pow(2).multiply(getA().getData())).add(x)
                .multiply(getB().getData().modInverse(getModulus())).mod(getModulus());
        BigInteger y = modSqrt(val, getModulus());
        if (y == null) {
            // no solution for given x was found
            return null;
        } else {
            return getPoint(x, y);
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementFp(value, this.getModulus());
    }

    private EllipticCurveOverFp computeWeierstrassEquivalent() {
        BigInteger weierstrassA = new BigInteger("3").subtract(this.getA().getData()
                .modPow(new BigInteger("2"), this.getModulus()));
        weierstrassA = weierstrassA.multiply(
                new BigInteger("3").multiply(this.getB().getData().modPow(new BigInteger("2"), this.getModulus()))
                        .modInverse(this.getModulus())).mod(this.getModulus());

        BigInteger weierstrassB = new BigInteger("2").multiply(
                this.getA().getData().modPow(new BigInteger("3"), this.getModulus())).subtract(
                new BigInteger("9").multiply(this.getA().getData()));
        weierstrassB = weierstrassB.multiply(
                new BigInteger("27").multiply(this.getB().getData().modPow(new BigInteger("3"), this.getModulus()))
                        .modInverse(this.getModulus())).mod(this.getModulus());

        Point wGen = toWeierstrass(this.getBasePoint());
        return new EllipticCurveOverFp(weierstrassA, weierstrassB, this.getModulus(), wGen.getX().getData(), wGen
                .getY().getData(), this.getBasePointOrder());
    }

    public Point toWeierstrass(Point mPoint) {
        if (mPoint.isAtInfinity()) {
            return mPoint;
        } else {
            BigInteger mX = mPoint.getX().getData();
            BigInteger mY = mPoint.getY().getData();

            BigInteger wX = mX
                    .multiply(this.getB().getData().modInverse(this.getModulus()))
                    .add(this
                            .getA()
                            .getData()
                            .multiply(new BigInteger("3").multiply(this.getB().getData()).modInverse(this.getModulus())))
                    .mod(this.getModulus());
            BigInteger wY = mY.multiply(this.getB().getData().modInverse(this.getModulus())).mod(this.getModulus());

            FieldElementFp fX = new FieldElementFp(wX, this.getModulus());
            FieldElementFp fY = new FieldElementFp(wY, this.getModulus());
            return new Point(fX, fY);
        }
    }

    public Point toMontgomery(Point wPoint) {
        if (wPoint.isAtInfinity()) {
            return wPoint;
        } else {
            BigInteger wX = wPoint.getX().getData();
            BigInteger wY = wPoint.getY().getData();

            BigInteger mX = wX
                    .subtract(
                            this.getA()
                                    .getData()
                                    .multiply(
                                            new BigInteger("3").multiply(this.getB().getData()).modInverse(
                                                    this.getModulus()))).multiply(this.getB().getData())
                    .mod(this.getModulus());
            BigInteger mY = wY.multiply(this.getB().getData());

            FieldElementFp fX = new FieldElementFp(mX, this.getModulus());
            FieldElementFp fY = new FieldElementFp(mY, this.getModulus());
            return new Point(fX, fY);
        }
    }

    /**
     * @return the weierstrassEquivalent
     */
    public EllipticCurveOverFp getWeierstrassEquivalent() {
        return weierstrassEquivalent;
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
