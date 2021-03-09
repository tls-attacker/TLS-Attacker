/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class InvalidCurvePointTest {

    public InvalidCurvePointTest() {
    }

    /**
     * Test points of small order.
     */
    @Test
    public void testSmallOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.smallOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    /**
     * Test points of alternative order.
     */
    @Test
    public void testAlternativeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.alternativeOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    /**
     * Test points of large order.
     */
    @Test
    public void testLargeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.largeOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    private boolean isOrderCorrect(InvalidCurvePoint invP) {
        EllipticCurve curve = CurveFactory.getCurve(invP.getNamedGroup());
        FieldElementFp bX = new FieldElementFp(invP.getPublicPointBaseX(), curve.getModulus());
        FieldElementFp bY = new FieldElementFp(invP.getPublicPointBaseY(), curve.getModulus());
        Point point = new Point(bX, bY);

        if (invP.getOrder().isProbablePrime(100)) {
            Point res = curve.mult(invP.getOrder(), point);
            return res.isAtInfinity();
        } else {
            for (int i = 1; i <= invP.getOrder().intValue(); i++) {
                Point res = curve.mult(BigInteger.valueOf(i), point);
                if (res.isAtInfinity()) {
                    return i == invP.getOrder().intValue();
                }
            }
        }
        return false;
    }

    private boolean pointsForGroupAreOrdered(NamedGroup group) {
        InvalidCurvePoint invP1 = InvalidCurvePoint.smallOrder(group);
        InvalidCurvePoint invP2 = InvalidCurvePoint.alternativeOrder(group);
        InvalidCurvePoint invP3 = InvalidCurvePoint.largeOrder(group);

        if (invP1 == null && (invP2 != null || invP3 != null)) {
            return false;
        } else if (invP2 == null && invP3 != null) {
            return false;
        } else if (invP2 != null && invP1.getOrder().compareTo(invP2.getOrder()) >= 0) {
            return false;
        } else if (invP3 != null && invP2 != null && invP2.getOrder().compareTo(invP3.getOrder()) >= 0) {
            return false;
        }
        return true;
    }

}
