/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.util;

import java.math.BigInteger;
import junit.framework.Assert;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class MathHelperTest {

    public MathHelperTest() {
    }

    /**
     * Test of intfloordiv method, of class MathHelper.
     */
    @Test
    public void testIntfloordiv_BigInteger_BigInteger() {
    }

    /**
     * Test of intceildiv method, of class MathHelper.
     */
    @Test
    public void testIntceildiv_BigInteger_BigInteger() {
    }

    /**
     * Test of intfloordiv method, of class MathHelper.
     */
    @Test
    public void testIntfloordiv_int_int() {
    }

    /**
     * Test of intceildiv method, of class MathHelper.
     */
    @Test
    public void testIntceildiv_int_int() {
    }

    /**
     * Test of extendedEuclid method, of class MathHelper.
     */
    @Test
    public void testExtendedEuclid() {
    }

    /**
     * Test of gcd method, of class MathHelper.
     */
    @Test
    public void testGcd() {
    }

    /**
     * Test of inverseMod method, of class MathHelper.
     */
    @Test
    public void testInverseMod() {
    }

    /**
     * Test of CRT method, of class MathHelper.
     */
    @Test
    public void testCRT() {
	BigInteger[] congs = { new BigInteger("3"), new BigInteger("4"), new BigInteger("5") };
	BigInteger[] moduli = { new BigInteger("2"), new BigInteger("3"), new BigInteger("2") };
	assertEquals(4, MathHelper.CRT(congs, moduli).intValue());

	// computes:
	// x == 2 mod 3
	// x == 3 mod 4
	// x == 1 mod 5
	BigInteger[] congs2 = { new BigInteger("2"), new BigInteger("3"), new BigInteger("1") };
	BigInteger[] moduli2 = { new BigInteger("3"), new BigInteger("4"), new BigInteger("5") };
	assertEquals(11, MathHelper.CRT(congs2, moduli2).intValue());
    }

}
