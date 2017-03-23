/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import java.math.BigInteger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ByteArrayOperationConcartenationTest {

    private ModifiableByteArray start;

    private byte[] expectedResult, result;

    public ByteArrayOperationConcartenationTest() {
    }

    @Before
    public void setUp() {
        start = new ModifiableByteArray();
        start.setOriginalValue(new byte[] { 1, 10 });
    }

    @Test
    public void testInsertThenXOR() {
        // input (insert4@1) xor 1,2,3 = 1 4 10 XOR 1 2 3,
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.insert(new byte[] { 4 }, 1);
        start.setModification(modifier);
        modifier.setPostModification(ByteArrayModificationFactory.xor(new byte[] { 1, 2, 3 }, 0));
        expectedResult = new byte[] { 0, 6, 9 };
        result = start.getValue();
        assertArrayEquals(expectedResult, result);
    }
}
