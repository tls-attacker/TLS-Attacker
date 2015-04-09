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
package de.rub.nds.tlsattacker.modifiablevariable.filter;

import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
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
public class ModificationApprovalTest {

    private ModifiableVariable<BigInteger> start;

    private ModificationFilter filter;

    private BigInteger expectedResult, result;

    public ModificationApprovalTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableVariable<>();
	start.setOriginalValue(BigInteger.TEN);
	int[] filtered = { 1, 3 };
	filter = ModificationFilterFactory.access(filtered);
	expectedResult = null;
	result = null;
    }

    /**
     * Test filter modification. The first and third modification are filtered
     * out so that no modification is visible.
     */
    @Test
    public void testAdd() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	modifier.setModificationFilter(filter);
	expectedResult = new BigInteger("10");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

	expectedResult = new BigInteger("11");
	result = start.getValue();
	assertEquals(expectedResult, result);

	expectedResult = new BigInteger("10");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
    }

}
