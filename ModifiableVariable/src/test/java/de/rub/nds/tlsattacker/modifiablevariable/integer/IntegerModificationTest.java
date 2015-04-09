/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.modifiablevariable.integer;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author dev
 */
public class IntegerModificationTest {

    private ModifiableVariable<Integer> start;

    private Integer expectedResult, result;

    public IntegerModificationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableVariable<>();
	start.setOriginalValue(10);
	expectedResult = null;
	result = null;
    }

    /**
     * Test of add method, of class IntegerModification.
     */
    @Test
    public void testAdd() {
	VariableModification<Integer> modifier = IntegerModificationFactory.add(1);
	start.setModification(modifier);
	expectedResult = 11;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of sub method, of class IntegerModification.
     */
    @Test
    public void testSub() {
	VariableModification<Integer> modifier = IntegerModificationFactory.sub(1);
	start.setModification(modifier);
	expectedResult = 9;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of xor method, of class IntegerModification.
     */
    @Test
    public void testXor() {
	VariableModification<Integer> modifier = IntegerModificationFactory.xor(2);
	start.setModification(modifier);
	expectedResult = 8;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of explicitValue method, of class IntegerModification.
     */
    @Test
    public void testExplicitValue() {
	VariableModification<Integer> modifier = IntegerModificationFactory.explicitValue(7);
	start.setModification(modifier);
	expectedResult = 7;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

}
