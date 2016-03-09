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
package de.rub.nds.tlsattacker.modifiablevariable.mlong;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class LongModificationTest {

    private ModifiableLong start;

    private Long expectedResult, result;

    @Before
    public void setUp() {

	start = new ModifiableLong();
	start.setOriginalValue(10L);
	expectedResult = null;
	result = null;

    }

    @Test
    public void testAdd() {

	VariableModification<Long> modifier = LongModificationFactory.add(1L);
	start.setModification(modifier);
	expectedResult = 11L;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Long(10L), start.getOriginalValue());

    }

    @Test
    public void testSub() {
	VariableModification<Long> modifier = LongModificationFactory.sub(1L);
	start.setModification(modifier);
	expectedResult = 9L;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Long(10L), start.getOriginalValue());
    }

    @Test
    public void testXor() {
	VariableModification<Long> modifier = LongModificationFactory.xor(2L);
	start.setModification(modifier);
	expectedResult = 8L;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Long(10L), start.getOriginalValue());
    }

    @Test
    public void testExplicitValue() {
	VariableModification<Long> modifier = LongModificationFactory.explicitValue(7L);
	start.setModification(modifier);
	expectedResult = 7L;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Long(10L), start.getOriginalValue());
    }

}
