/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import static org.junit.Assert.assertTrue;
import java.math.BigInteger;
import org.junit.Before;
import org.junit.Test;

/**
 * Test values from for curve P192: http://point-at-infinity.org/ecc/nisttv
 * Curve: P192 ------------- k = 1 x =
 * 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012 y =
 * 07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
 *
 * k = 2 x = DAFEBF5828783F2AD35534631588A3F629A70FB16982A888 y =
 * DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB
 *
 * k = 3 x = 76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA y =
 * 782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD
 *
 * k = 4 x = 35433907297CC378B0015703374729D7A4FE46647084E4BA y =
 * A2649984F2135C301EA3ACB0776CD4F125389B311DB3BE32
 *
 * k = 5 x = 10BB8E9840049B183E078D9C300E1605590118EBDD7FF590 y =
 * 31361008476F917BADC9F836E62762BE312B72543CCEAEA1
 */

public class ECComputerTest {

    public ECComputerTest() {
    }

    @Before
    public void setUp() {
    }

    // Testing dbl method with P(x,y)
    @Test
    public void dblTest() {
        // init secp192r1 curve
        Curve c = new Curve("secp192r1", new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
                new BigInteger("6277101735386680763835789423207666416083908700390324961276"), new BigInteger(
                        "2455155546008943817740293915197451784769108058161191238065"), 192);

        // init ECComputer
        ECComputer ecc = new ECComputer(c, null);

        // Values for P (= 1P)
        BigInteger x1 = new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        BigInteger y1 = new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        Point p1 = new Point(x1, y1);

        // Values for 2P (= P doubled)
        BigInteger x2 = new BigInteger("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        BigInteger y2 = new BigInteger("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);
        Point p2 = new Point(x2, y2);

        // double P with method ECCompuer.dbl
        Point p1_dbl = new Point();
        try {
            p1_dbl = ecc.dbl(p1);
        } catch (DivisionException e) {
            System.out.println("DivisionException thrown in ECComputerTest.dblTest");
            assertTrue(false);
        }
        assertTrue(p1_dbl.equals(p2));
    }

    // Testing dbl method with Infinitycheck
    @Test
    public void dblInfTest() {
        // init secp192r1 curve
        Curve c = new Curve("secp192r1", new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
                new BigInteger("6277101735386680763835789423207666416083908700390324961276"), new BigInteger(
                        "2455155546008943817740293915197451784769108058161191238065"), 192);

        // init ECComputer
        ECComputer ecc = new ECComputer(c, null);

        // Values for P (= 1P)
        BigInteger x1 = new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        BigInteger y1 = new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        Point p1 = new Point(x1, y1);

        System.out.println("P set: \n" + p1.toString());

        // set p1 to infinity
        p1.setInfinity(true);

        // double P with method ECCompuer.dbl with infinity check
        Point p1_dbl = new Point();
        try {
            p1_dbl = ecc.dbl(p1, true);
        } catch (DivisionException e) {
            System.out.println("DivisionException thrown in ECComputerTest.dblInfTest");
            assertTrue(false);
        }
        // Print Values
        assertTrue(p1_dbl.equals(p1));

        // Testing add method with P(x,0)
        p1.setY(new BigInteger("0", 10));

        try {
            p1_dbl = ecc.dbl(p1, true); // double
        } catch (DivisionException e) {
            System.out.println("DivisionException thrown in ECComputerTest.dblInfTest");
            assertTrue(false);
        }
        // Print Values
        assertTrue(p1_dbl.isInfinity());

        // if dblTest() passed and this test passed until here, method
        // ECComputer.dbl(p, true) works properly, as
        // ECComputer.dbl(p) is called and was already tested.
    }

    // Testing add method with 2P + 2P =? 5P
    @Test
    public void addTest() {
        // init secp192r1 curve
        Curve c = new Curve("secp192r1", new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
                new BigInteger("6277101735386680763835789423207666416083908700390324961276"), new BigInteger(
                        "2455155546008943817740293915197451784769108058161191238065"), 192);

        // init ECComputer
        ECComputer ecc = new ECComputer(c, null);

        // Values for 2P
        BigInteger x2 = new BigInteger("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        BigInteger y2 = new BigInteger("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);
        Point p2 = new Point(x2, y2);

        // Values for 3P
        BigInteger x3 = new BigInteger("76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA", 16);
        BigInteger y3 = new BigInteger("782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD", 16);
        Point p3 = new Point(x3, y3);

        // Values for 5P
        BigInteger x5 = new BigInteger("10BB8E9840049B183E078D9C300E1605590118EBDD7FF590", 16);
        BigInteger y5 = new BigInteger("31361008476F917BADC9F836E62762BE312B72543CCEAEA1", 16);
        Point p5 = new Point(x5, y5);

        // calc 2P + 3P with ECComputer.add
        Point p5_add = new Point();
        try {
            p5_add = ecc.add(p2, p3);
        } catch (DivisionException e) {
            System.out.println("DivisionException thrown in ECComputerTest.addTest");
            assertTrue(false);
        }
        assertTrue(p5_add.equals(p5));
    }

    // Testing add method with Infinitycheck
    @Test
    public void addInfTest() {
        // init secp192r1 curve
        Curve c = new Curve("secp192r1", new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
                new BigInteger("6277101735386680763835789423207666416083908700390324961276"), new BigInteger(
                        "2455155546008943817740293915197451784769108058161191238065"), 192);

        // init ECComputer
        ECComputer ecc = new ECComputer(c, null);

        // calc 2P + 3P with ECComputer.add
        Point p5_add = new Point();
        // Values for 2P
        BigInteger x2 = new BigInteger("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        BigInteger y2 = new BigInteger("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);
        Point p2 = new Point(x2, y2);

        // Values for 3P
        BigInteger x3 = new BigInteger("76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA", 16);
        BigInteger y3 = new BigInteger("782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD", 16);
        Point p3 = new Point(x3, y3);

        // instanciate Point object
        Point p5 = new Point();

        try {
            // test with p2 = infinity
            assertTrue(ecc.add(null, p3, true).equals(p3));
            p2.setInfinity(true);
            assertTrue(ecc.add(p2, p3, true).equals(p3));

            // reset p2
            p2.setInfinity(false);

            // test with p3 = infinity
            assertTrue(ecc.add(p2, null, true).equals(p2));
            p3.setInfinity(true);
            assertTrue(ecc.add(p2, p3, true).equals(p2));

            // reset p3
            p3.setInfinity(false);

            // test equal coordinate behavour
            // 2P + 2P =? 4P (doubled)
            assertTrue(ecc.add(p2, p2, true).equals(ecc.dbl(p2, true)));
            // 2P + 3P =? infinity if x_p2 = x_p3
            p2.setX(p3.getX());
            assertTrue(ecc.add(p2, p3, true).isInfinity());
        } catch (DivisionException e) {
            System.out.println("DivisionException thrown in ECComputerTest.addInfTest");
            assertTrue(false);
        }
        // if addTest() passed and this test passed until here, method
        // ECComputer.add(p, q, true) works properly, as
        // ECComputer.add(p, q) is called and was already tested.
    }
}
