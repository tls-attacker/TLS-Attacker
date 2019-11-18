/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.util.Random;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class PointFormatterTest {

    public PointFormatterTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of formatToByteArray method, of class PointFormatter.
     */
    @Test
    public void cyclicTest() {
        for (int i = 0; i < 100; i++) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isStandardCurve()) {
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    Point point = curve.getPoint(new BigInteger(i % 257, new Random(i)), new BigInteger(i % 257,
                            new Random(i)));
                    byte[] byteArray1 = PointFormatter.formatToByteArray(point, ECPointFormat.UNCOMPRESSED);
                    point = PointFormatter.formatFromByteArray(group, byteArray1);
                    byte[] byteArray2 = PointFormatter.formatToByteArray(point, ECPointFormat.UNCOMPRESSED);
                    assertArrayEquals(byteArray1, byteArray2);
                }
            }
        }
    }
}
