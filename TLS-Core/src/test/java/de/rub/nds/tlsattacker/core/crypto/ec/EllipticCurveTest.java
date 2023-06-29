/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Testing EllipticCurve, CurveFactory, EllipticCurveOverFp and EllipticCurveOverF2m */
public class EllipticCurveTest {

    /*
     * Please notice that these tests can provide correctness only in a probabilistic sense. (Though with a very high
     * probability, since the curve parameters are very large.)
     */

    private Random rnd;
    private Point inf;

    @BeforeEach
    public void setUp() {
        this.rnd = new Random();
        this.inf = new Point();
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            // Exclude FFDHE and EXPLICIT groups from this test
            names = {"^FFDHE[0-9]*", "^EXPLICIT_.*"},
            mode = EnumSource.Mode.MATCH_NONE)
    @Tag(TestCategories.SLOW_TEST)
    public void test(NamedGroup providedNamedGroup) {
        EllipticCurve curve = CurveFactory.getCurve(providedNamedGroup);
        Point basePoint = curve.getBasePoint();
        BigInteger basePointOrder = curve.getBasePointOrder();

        this.assertCurveParameters(curve, basePoint);
        this.assertCurveGroupLaws(curve, basePoint, basePointOrder);
        this.assertCurveArithmetic(curve, basePoint, basePointOrder);
        this.assertDecompression(curve, basePoint);
    }

    private void assertCurveParameters(EllipticCurve curve, Point basePoint) {
        assertTrue(curve.isOnCurve(basePoint));

        // Constructing a point, that is not on the curve, to ensure that the
        // first test was no false positive.
        BigInteger x = basePoint.getFieldX().getData();
        BigInteger y = basePoint.getFieldY().getData();
        BigInteger wrongX = x.add(BigInteger.ONE);
        Point wrongPoint = curve.getPoint(wrongX, y);

        assertFalse(curve.isOnCurve(wrongPoint));
    }

    private void assertCurveGroupLaws(
            EllipticCurve curve, Point basePoint, BigInteger basePointOrder) {
        Point inv = curve.inverse(basePoint);

        assertNotEquals(inf, basePoint);
        assertNotEquals(inf, inv);
        assertNotEquals(inv, basePoint);

        // -0 == 0
        assertEquals(inf, curve.inverse(inf));

        // ord(p) * p == 0
        Point result = curve.mult(basePointOrder, basePoint);
        assertEquals(inf, result);

        // p - p == 0
        result = curve.add(basePoint, inv);
        assertEquals(inf, result);

        // (ord(p)-1) * p == -p
        result = curve.mult(basePointOrder.subtract(BigInteger.ONE), basePoint);
        assertEquals(inv, result);

        // (ord(p)+1) * p == p
        result = curve.mult(basePointOrder.add(BigInteger.ONE), basePoint);
        assertEquals(basePoint, result);

        // 0 + 0 == 0
        result = curve.add(inf, inf);
        assertEquals(inf, result);

        // 0 + p == p
        result = curve.add(inf, basePoint);
        assertEquals(basePoint, result);

        // p + 0 == p
        result = curve.add(basePoint, inf);
        assertEquals(basePoint, result);
    }

    private void assertCurveArithmetic(
            EllipticCurve curve, Point basePoint, BigInteger basePointOrder) {
        for (int i = 0; i < 2; i++) {
            // Testing for a random r
            // This should work for r>ord(p) too
            BigInteger random = new BigInteger(basePointOrder.bitLength() + 1, rnd);
            if (random.equals(basePointOrder)) {
                random = random.flipBit(0);
            }
            Point inv = curve.inverse(basePoint);

            // r*p+(ord(p)-r)*p == 0
            Point r1 = curve.mult(random, basePoint);
            Point r2 = curve.mult(basePointOrder.subtract(random), basePoint);
            Point result = curve.add(r1, r2);
            assertNotEquals(inf, r1);
            assertNotEquals(inf, r2);
            assertEquals(inf, result);
            assertEquals(r1, curve.inverse(r2));
            assertEquals(r2, curve.inverse(r1));

            // (r+1)*p+(ord(p)-r)*p == p
            r1 = curve.mult(random.add(BigInteger.ONE), basePoint);
            result = curve.add(r1, r2);
            assertNotEquals(r1, inf);
            assertEquals(basePoint, result);

            // (r-1)*p+(ord(p)-r)*p == -p
            r1 = curve.mult(random.subtract(BigInteger.ONE), basePoint);
            result = curve.add(r1, r2);
            assertNotEquals(r1, inf);
            assertEquals(inv, result);
        }
    }

    private void assertDecompression(EllipticCurve curve, Point basePoint) {
        Point decompressed = curve.createAPointOnCurve(basePoint.getFieldX().getData());

        // two points share the same x-coordinate - apply inverse if necessary
        if (!decompressed.getFieldY().getData().equals(basePoint.getFieldY().getData())) {
            decompressed = curve.inverse(decompressed);
        }
        assertEquals(decompressed, basePoint);

        if (curve instanceof EllipticCurveOverF2m) {
            Point decompressed0 = curve.createAPointOnCurve(BigInteger.ZERO);
            assertTrue(curve.isOnCurve(decompressed0));
        }
    }
}
