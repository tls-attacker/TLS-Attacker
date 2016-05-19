/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.filter;

import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModificationApprovalTest {

    private ModifiableBigInteger start;

    private ModificationFilter filter;

    private BigInteger expectedResult, result;

    public ModificationApprovalTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableBigInteger();
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
