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
package de.rub.nds.tlsattacker.modifiablevariable.biginteger;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BigIntegerModificationTest {

    private ModifiableBigInteger start;

    private BigInteger expectedResult, result;

    public BigIntegerModificationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableBigInteger();
	start.setOriginalValue(BigInteger.TEN);
	expectedResult = null;
	result = null;
    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testAdd() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	expectedResult = new BigInteger("11");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of sub method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testSub() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.sub(BigInteger.ONE);
	start.setModification(modifier);
	expectedResult = new BigInteger("9");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of xor method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testXor() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.xor(new BigInteger("2"));
	start.setModification(modifier);
	expectedResult = new BigInteger("8");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of explicitValue method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testExplicitValue() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.explicitValue(new BigInteger("7"));
	start.setModification(modifier);
	expectedResult = new BigInteger("7");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testIsOriginalValueModified() {
	assertFalse(start.isOriginalValueModified());
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ZERO);
	start.setModification(modifier);
	assertFalse(start.isOriginalValueModified());
	modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	assertTrue(start.isOriginalValueModified());
    }
}
