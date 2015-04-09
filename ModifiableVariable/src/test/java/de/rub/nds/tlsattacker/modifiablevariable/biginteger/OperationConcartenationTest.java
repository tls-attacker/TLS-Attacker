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
package de.rub.nds.tlsattacker.modifiablevariable.biginteger;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author dev
 */
public class OperationConcartenationTest {

    private ModifiableVariable<BigInteger> start;

    private BigInteger expectedResult, result;

    public OperationConcartenationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableVariable<BigInteger>();
	start.setOriginalValue(BigInteger.TEN);
    }

    @Test
    public void testAddThenMultiply() {
	// (input + 4) ^ 3 = (10 + 4) ^ 3 = 13
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add("4");
	start.setModification(modifier);
	modifier.setPostModification(BigIntegerModificationFactory.xor("3"));
	expectedResult = new BigInteger("13");
	result = start.getValue();
	assertEquals(expectedResult, result);
    }

    @Test
    public void testAddThenMultiplyWithInnerClass() {
	// (input + 4) ^ 3 = (10 + 4) ^ 3 = 13
	start.setModification(new VariableModification<BigInteger>() {

	    @Override
	    protected BigInteger modifyImplementationHook(BigInteger input) {
		return input.add(new BigInteger("4")).xor(new BigInteger("3"));
	    }
	});
	expectedResult = new BigInteger("13");
	result = start.getValue();
	assertEquals(expectedResult, result);
    }
}
