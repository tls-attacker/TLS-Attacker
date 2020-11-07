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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A Montgomery Curve that internally uses a Weierstrass Curve
 */
public class SimulatedMontgomeryCurve extends EllipticCurveOverFp {

    private static final Logger LOGGER = LogManager.getLogger();

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
        Point weierstrassP = toWeierstrass(p);
        return getWeierstrassEquivalent().isOnCurve(weierstrassP);
    }

    @Override
    protected Point inverseAffine(Point p) {
        Point weierstrassP = toWeierstrass(p);
        Point weierstrassRes = getWeierstrassEquivalent().inverseAffine(weierstrassP);
        return toMontgomery(weierstrassRes);
    }

    @Override
    protected Point additionFormular(Point p, Point q) {
        Point weierstrassP = toWeierstrass(p);
        Point weierstrassQ = toWeierstrass(q);
        Point weierstrassRes = getWeierstrassEquivalent().additionFormular(weierstrassP, weierstrassQ);
        return toMontgomery(weierstrassRes);
    }

    @Override
    public Point createAPointOnCurve(BigInteger x) {
        BigInteger val =
            x.pow(3).add(x.pow(2).multiply(getA().getData())).add(x)
                .multiply(getB().getData().modInverse(getModulus())).mod(getModulus());
        BigInteger y = modSqrt(val, getModulus());
        if (y == null) {
            LOGGER.warn("Could not create a point on Curve. Creating with y == 0");
            return getPoint(x, BigInteger.ZERO);
        } else {
            return getPoint(x, y);
        }
    }

    @Override
    public FieldElement createFieldElement(BigInteger value) {
        return new FieldElementFp(value, this.getModulus());
    }

    private EllipticCurveOverFp computeWeierstrassEquivalent() {
        BigInteger weierstrassA =
            new BigInteger("3").subtract(this.getA().getData().modPow(new BigInteger("2"), this.getModulus()));
        weierstrassA =
            weierstrassA.multiply(
                new BigInteger("3").multiply(this.getB().getData().modPow(new BigInteger("2"), this.getModulus()))
                    .modInverse(this.getModulus())).mod(this.getModulus());

        BigInteger weierstrassB =
            new BigInteger("2").multiply(this.getA().getData().modPow(new BigInteger("3"), this.getModulus()))
                .subtract(new BigInteger("9").multiply(this.getA().getData()));
        weierstrassB =
            weierstrassB.multiply(
                new BigInteger("27").multiply(this.getB().getData().modPow(new BigInteger("3"), this.getModulus()))
                    .modInverse(this.getModulus())).mod(this.getModulus());

        Point weierstrassGen = toWeierstrass(this.getBasePoint());
        return new EllipticCurveOverFp(weierstrassA, weierstrassB, this.getModulus(), weierstrassGen.getX().getData(),
            weierstrassGen.getY().getData(), this.getBasePointOrder());
    }

    public Point toWeierstrass(Point mpoint) {
        if (mpoint.isAtInfinity()) {
            return mpoint;
        } else {
            BigInteger mx = mpoint.getX().getData();
            BigInteger my = mpoint.getY().getData();

            BigInteger weierstrassX =
                mx.multiply(this.getB().getData().modInverse(this.getModulus()))
                    .add(
                        this.getA()
                            .getData()
                            .multiply(new BigInteger("3").multiply(this.getB().getData()).modInverse(this.getModulus())))
                    .mod(this.getModulus());
            BigInteger weierstrassY =
                my.multiply(this.getB().getData().modInverse(this.getModulus())).mod(this.getModulus());

            FieldElementFp fieldX = new FieldElementFp(weierstrassX, this.getModulus());
            FieldElementFp fieldY = new FieldElementFp(weierstrassY, this.getModulus());
            return new Point(fieldX, fieldY);
        }
    }

    public Point toMontgomery(Point weierstrassPoint) {
        if (weierstrassPoint.isAtInfinity()) {
            return weierstrassPoint;
        } else {
            BigInteger weierstrassX = weierstrassPoint.getX().getData();
            BigInteger weierstrassY = weierstrassPoint.getY().getData();

            BigInteger mx =
                weierstrassX
                    .subtract(
                        this.getA()
                            .getData()
                            .multiply(new BigInteger("3").multiply(this.getB().getData()).modInverse(this.getModulus())))
                    .multiply(this.getB().getData()).mod(this.getModulus());
            BigInteger my = weierstrassY.multiply(this.getB().getData());

            FieldElementFp fieldX = new FieldElementFp(mx, this.getModulus());
            FieldElementFp fieldY = new FieldElementFp(my, this.getModulus());
            return new Point(fieldX, fieldY);
        }
    }

    /**
     * @return the weierstrassEquivalent
     */
    public EllipticCurveOverFp getWeierstrassEquivalent() {
        return weierstrassEquivalent;
    }
}
