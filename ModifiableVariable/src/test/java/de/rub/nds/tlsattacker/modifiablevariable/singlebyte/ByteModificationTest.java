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
package de.rub.nds.tlsattacker.modifiablevariable.singlebyte;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Florian Pfützenreuter
 */
public class ByteModificationTest {

    private ModifiableByte start;

    private Byte expectedResult, result;

    public ByteModificationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableByte();
	start.setOriginalValue(new Byte("10"));
	expectedResult = null;
	result = null;
    }

    /**
     * Test of add method, of class ByteModificationFactory.
     */
    @Test
    public void testAdd() {
	VariableModification<Byte> modifier = ByteModificationFactory.add(new Byte("1"));
	start.setModification(modifier);
	expectedResult = new Byte("11");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(new Byte("10"), start.getOriginalValue());
    }

    /**
     * Test of sub method, of class ByteModificationFactory.
     */
    @Test
    public void testSub() {
	VariableModification<Byte> modifier = ByteModificationFactory.sub(new Byte("1"));
	start.setModification(modifier);
	expectedResult = new Byte("9");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(new Byte("10"), start.getOriginalValue());
    }

    /**
     * Test of xor method, of class ByteModificationFactory.
     */
    @Test
    public void testXor() {
	VariableModification<Byte> modifier = ByteModificationFactory.xor(new Byte("2"));
	start.setModification(modifier);
	expectedResult = new Byte("8");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(new Byte("10"), start.getOriginalValue());
    }

    /**
     * Test of explicitValue method, of class ByteModificationFactory.
     */
    @Test
    public void testExplicitValue() {
	VariableModification<Byte> modifier = ByteModificationFactory.explicitValue(new Byte("7"));
	start.setModification(modifier);
	expectedResult = new Byte("7");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(new Byte("10"), start.getOriginalValue());
    }

}
