/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
