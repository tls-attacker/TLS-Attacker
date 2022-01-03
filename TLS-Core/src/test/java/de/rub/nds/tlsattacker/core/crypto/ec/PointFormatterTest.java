/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.math.BigInteger;
import java.util.Random;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class PointFormatterTest {

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    public PointFormatterTest() {
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
    @Category(IntegrationTests.class)
    public void cyclicTest() {
        for (int i = 0; i < 100; i++) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isStandardCurve()) {
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    Point point =
                        curve.getPoint(new BigInteger(i % 257, new Random(i)), new BigInteger(i % 257, new Random(i)));
                    byte[] byteArray1 = PointFormatter.formatToByteArray(group, point, ECPointFormat.UNCOMPRESSED);
                    point = PointFormatter.formatFromByteArray(group, byteArray1);
                    byte[] byteArray2 = PointFormatter.formatToByteArray(group, point, ECPointFormat.UNCOMPRESSED);
                    assertArrayEquals(byteArray1, byteArray2);
                }
            }
        }
    }

    @Test
    @Category(IntegrationTests.class)
    public void compressionFormatCyclicTest() {
        for (int i = 1; i < 50; i++) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isStandardCurve()) {
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    BigInteger scalar = new BigInteger(i % 257, new Random(i));
                    Point point = curve.mult(scalar, curve.getBasePoint());
                    ECPointFormat format;
                    if (curve instanceof EllipticCurveOverFp) {
                        format = ECPointFormat.ANSIX962_COMPRESSED_PRIME;
                    } else {
                        format = ECPointFormat.ANSIX962_COMPRESSED_CHAR2;
                    }
                    byte[] byteArray1 = PointFormatter.formatToByteArray(group, point, format);
                    point = PointFormatter.formatFromByteArray(group, byteArray1);
                    byte[] byteArray2 = PointFormatter.formatToByteArray(group, point, format);
                    assertArrayEquals(byteArray1, byteArray2);
                }
            }
        }
    }

    @Test
    public void compressionFormatTest() {
        byte[] secp160r1Base = ArrayConverter.hexStringToByteArray("024A96B5688EF573284664698968C38BB913CBFC82");
        byte[] secp224k1Base =
            ArrayConverter.hexStringToByteArray("03A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C");
        byte[] secp521r1Base = ArrayConverter.hexStringToByteArray(
            "0200C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66");

        byte[] sect193r2Base =
            ArrayConverter.hexStringToByteArray("0300D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F");
        byte[] sect233r1Base =
            ArrayConverter.hexStringToByteArray("0300FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B");
        byte[] sect571k1Base = ArrayConverter.hexStringToByteArray(
            "02026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972");

        byte[] compressed = PointFormatter.formatToByteArray(NamedGroup.SECP160R1,
            CurveFactory.getCurve(NamedGroup.SECP160R1).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        assertArrayEquals(secp160r1Base, compressed);

        compressed = PointFormatter.formatToByteArray(NamedGroup.SECP224K1,
            CurveFactory.getCurve(NamedGroup.SECP224K1).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        assertArrayEquals(secp224k1Base, compressed);

        compressed = PointFormatter.formatToByteArray(NamedGroup.SECP521R1,
            CurveFactory.getCurve(NamedGroup.SECP521R1).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        assertArrayEquals(secp521r1Base, compressed);

        compressed = PointFormatter.formatToByteArray(NamedGroup.SECT193R2,
            CurveFactory.getCurve(NamedGroup.SECT193R2).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        assertArrayEquals(sect193r2Base, compressed);

        compressed = PointFormatter.formatToByteArray(NamedGroup.SECT233R1,
            CurveFactory.getCurve(NamedGroup.SECT233R1).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        assertArrayEquals(sect233r1Base, compressed);

        compressed = PointFormatter.formatToByteArray(NamedGroup.SECT571K1,
            CurveFactory.getCurve(NamedGroup.SECT571K1).getBasePoint(), ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        assertArrayEquals(sect571k1Base, compressed);
    }
}
