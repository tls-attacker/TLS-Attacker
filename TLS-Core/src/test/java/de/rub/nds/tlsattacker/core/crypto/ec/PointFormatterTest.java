/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.math.BigInteger;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class PointFormatterTest {

    /** Test of formatToByteArray method, of class PointFormatter. */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void cyclicTest() {
        for (int i = 0; i < 25; i++) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isStandardCurve()) {
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    Point point =
                            curve.getPoint(
                                    new BigInteger(i, new Random(i)),
                                    new BigInteger(i, new Random(i)));
                    byte[] byteArray1 =
                            PointFormatter.formatToByteArray(
                                    group, point, ECPointFormat.UNCOMPRESSED);
                    point = PointFormatter.formatFromByteArray(group, byteArray1);
                    byte[] byteArray2 =
                            PointFormatter.formatToByteArray(
                                    group, point, ECPointFormat.UNCOMPRESSED);
                    assertArrayEquals(byteArray1, byteArray2);
                }
            }
        }
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void compressionFormatCyclicTest() {
        for (int i = 1; i < 25; i++) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isStandardCurve()) {
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    BigInteger scalar = new BigInteger(i, new Random(i));
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

    /**
     * Provides test vectors of format (providedNamedGroup, expectedCompressedBasePoint) for {@link
     * #testCompressionFormat(NamedGroup, String)}.
     */
    public static Stream<Arguments> provideCompressionFormatTestVectors() {
        return Stream.of(
                Arguments.of(NamedGroup.SECP160R1, "024A96B5688EF573284664698968C38BB913CBFC82"),
                Arguments.of(
                        NamedGroup.SECP224K1,
                        "03A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"),
                Arguments.of(
                        NamedGroup.SECP521R1,
                        "0200C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
                Arguments.of(
                        NamedGroup.SECT193R2,
                        "0300D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F"),
                Arguments.of(
                        NamedGroup.SECT233R1,
                        "0300FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B"),
                Arguments.of(
                        NamedGroup.SECT571K1,
                        "02026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972"));
    }

    @ParameterizedTest
    @MethodSource("provideCompressionFormatTestVectors")
    @Tag(TestCategories.SLOW_TEST)
    public void testCompressionFormat(
            NamedGroup providedNamedGroup, String expectedCompressedBasePoint) {
        byte[] expectedCompressedBasePointBytes =
                ArrayConverter.hexStringToByteArray(expectedCompressedBasePoint);
        EllipticCurve curve = CurveFactory.getCurve(providedNamedGroup);
        ECPointFormat pointFormat =
                curve instanceof EllipticCurveOverFp
                        ? ECPointFormat.ANSIX962_COMPRESSED_PRIME
                        : ECPointFormat.ANSIX962_COMPRESSED_CHAR2;
        byte[] actualCompressedBasePointBytes =
                PointFormatter.formatToByteArray(
                        providedNamedGroup, curve.getBasePoint(), pointFormat);
        assertArrayEquals(expectedCompressedBasePointBytes, actualCompressedBasePointBytes);
    }
}
