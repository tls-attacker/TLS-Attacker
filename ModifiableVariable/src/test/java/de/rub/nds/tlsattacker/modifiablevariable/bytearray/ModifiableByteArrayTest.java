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
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de> todo write tests here
 */
public class ModifiableByteArrayTest {

    private ModifiableByteArray start;

    private byte[] expectedResult, result;

    private byte[] originalValue;

    private byte[] modification1;

    private byte[] modification2;

    private static Logger LOGGER = LogManager.getLogger(ModifiableByteArray.class);

    @Before
    public void setUp() {
	originalValue = new byte[] { (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6 };
	modification1 = new byte[] { (byte) 2, (byte) 3 };
	modification2 = new byte[] { (byte) 2, (byte) 1, (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5,
		(byte) 6 };
	start = new ModifiableByteArray();
	start.setOriginalValue(originalValue);
    }

    /**
     * Test of setValue method, of class ModifiableByteArray.
     */
    @Test
    public void testSetValue() {
	LOGGER.info("setValue");
	ModifiableByteArray instance = new ModifiableByteArray();
	byte[] test = originalValue.clone();
	instance.setOriginalValue(test);
	assertArrayEquals(originalValue, instance.getValue());
    }

    /**
     * Test of setExplicitValue method, of class ModifiableByteArray.
     */
    @Test
    public void testExplicitValue() {
        LOGGER.info("testExplicitValue");
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(modification1);
        start.setModification(modifier);
        assertArrayEquals(modification1, start.getValue());
    }

     /**
     * Test of setXorFirstBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testXorFirstBytes() {
        LOGGER.info("testXorFirstBytes");
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(modification1, 0);
        start.setModification(modifier);

        byte[] expResult = originalValue.clone();
        for (int i = 0; i < modification1.length; i++) {
            expResult[i] = (byte) (originalValue[i] ^ modification1[i]);
        }
        
        assertArrayEquals(expResult, start.getValue());

        VariableModification<byte[]> modifier2 = ByteArrayModificationFactory.xor(modification2, 0);
        start.setModification(modifier2);

        Exception e = null;
        try {
            start.getValue();
        } catch (ArrayIndexOutOfBoundsException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
    }
    
    /**
     * Test of setXorLastBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testXorLastBytes() {
        LOGGER.info("testXorLastBytes");

        byte[] expResult = originalValue.clone();
        int first = expResult.length - modification1.length;
        for (int i = 0; i < modification1.length; i++) {
            expResult[first + i] = (byte) (originalValue[first + i]
                    ^ modification1[i]);
        }
        
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(modification1, first);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: "
                + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());

        VariableModification<byte[]> modifier2 = ByteArrayModificationFactory.xor(modification2, first);
        start.setModification(modifier2);

        Exception e = null;
        try {
            start.getValue();
        } catch (ArrayIndexOutOfBoundsException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
    }
    
    /**
     * Test of setPrependBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testPrependBytes() {
        LOGGER.info("testPrependBytes");
        // TODO Robert
    }

    /**
     * Test of setAppendBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testAppendBytes() {
        LOGGER.info("testAppendBytes");
        // TODO Robert
    }

    /**
     * Test of setDeleteLastBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testDeleteLastBytes() {
        LOGGER.info("testDeleteLastBytes");
        // TODO Robert
    }

    /**
     * Test of setDeleteFirstBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testDeleteFirstBytes() {
        LOGGER.info("testDeleteFirstBytes");
        // TODO Robert
    }

    /**
     * Test of setInsertBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testInsertBytes() {
        LOGGER.info("testInsertBytes");
        // TODO Robert
    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testIsOriginalValueModified() {
	assertFalse(start.isOriginalValueModified());
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] {}, 0);
	start.setModification(modifier);
	assertFalse(start.isOriginalValueModified());
	modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
	start.setModification(modifier);
	assertTrue(start.isOriginalValueModified());
	modifier = ByteArrayModificationFactory.xor(new byte[] { 0, 0 }, originalValue.length - 2);
	start.setModification(modifier);
	assertFalse(start.isOriginalValueModified());
    }
}
