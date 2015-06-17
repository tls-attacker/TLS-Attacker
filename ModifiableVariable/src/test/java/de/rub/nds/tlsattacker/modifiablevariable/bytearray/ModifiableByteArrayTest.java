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

    // /**
    // * Test of setExplicitValue method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testExplicitValue() {
    // LOGGER.info("testExplicitValue");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setExplicitValue(modification1);
    //
    // assertArrayEquals(modification1, instance.getValue());
    // }
    //
    // /**
    // * Test of setXorFirstBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testXorFirstBytes() {
    // LOGGER.info("testXorFirstBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setXorFirstBytes(modification1);
    //
    // byte[] expResult = originalValue.clone();
    // for (int i = 0; i < modification1.length; i++) {
    // expResult[i] = (byte) (originalValue[i] ^ modification1[i]);
    // }
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    //
    // instance.setXorFirstBytes(modification2);
    //
    // Exception e = null;
    // try {
    // instance.getValue();
    // } catch (ArrayIndexOutOfBoundsException ae) {
    // e = ae;
    // LOGGER.debug(ae.getLocalizedMessage());
    // }
    // assertNotNull(e);
    // }
    //
    // /**
    // * Test of setXorLastBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testXorLastBytes() {
    // LOGGER.info("testXorLastBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setXorLastBytes(modification1);
    //
    // byte[] expResult = originalValue.clone();
    // int start = expResult.length - modification1.length;
    // for (int i = 0; i < modification1.length; i++) {
    // expResult[start + i] = (byte) (originalValue[start + i] ^
    // modification1[i]);
    // }
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    //
    // instance.setXorLastBytes(modification2);
    //
    // Exception e = null;
    // try {
    // instance.getValue();
    // } catch (ArrayIndexOutOfBoundsException ae) {
    // e = ae;
    // LOGGER.debug(ae.getLocalizedMessage());
    // }
    // assertNotNull(e);
    // }
    //
    // /**
    // * Test of setPrependBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testPrependBytes() {
    // LOGGER.info("testPrependBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setPrependBytes(modification1);
    //
    // byte[] expResult = ArrayConverter.concatenate(modification1,
    // originalValue);
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setAppendBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testAppendBytes() {
    // LOGGER.info("testAppendBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setAppendBytes(modification1);
    //
    // byte[] expResult = ArrayConverter.concatenate(originalValue,
    // modification1);
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setDeleteLastBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testDeleteLastBytes() {
    // LOGGER.info("testDeleteLastBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setDeleteFirstBytes(2);
    //
    // byte[] expResult = Arrays.copyOfRange(originalValue, 2,
    // originalValue.length);
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setDeleteFirstBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testDeleteFirstBytes() {
    // LOGGER.info("testDeleteFirstBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setDeleteLastBytes(2);
    //
    // byte[] expResult = Arrays.copyOf(originalValue, originalValue.length -
    // 2);
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setDeleteBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testSetDeleteBytes() {
    // LOGGER.info("testDeleteBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setDeleteBytes(3);
    // instance.setPosition(2);
    //
    // byte[] expResult = new byte[]{(byte) 0, (byte) 1, (byte) 5, (byte) 6};
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setInsertBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testInsertBytes() {
    // LOGGER.info("testInsertBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setInsertBytes(modification1);
    // instance.setPosition(4);
    //
    // byte[] expResult = ArrayConverter.concatenate(
    // Arrays.copyOf(originalValue, 4), modification1,
    // Arrays.copyOfRange(originalValue, 4, originalValue.length));
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    // }
    //
    // /**
    // * Test of setXorBytes method, of class ModifiableByteArray.
    // */
    // @Test
    // public void testXorBytes() {
    // LOGGER.info("testXorBytes");
    // ModifiableByteArray instance = new ModifiableByteArray();
    // instance.setValue(originalValue);
    // instance.setXorBytes(modification1);
    // instance.setPosition(2);
    //
    // byte[] expResult = originalValue.clone();
    // expResult[2] = 0;
    // expResult[3] = 0;
    //
    // LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
    // LOGGER.debug("Computed: " +
    // ArrayConverter.bytesToHexString(instance.getValue()));
    // assertArrayEquals(expResult, instance.getValue());
    //
    // instance.setPosition(6);
    // Exception e = null;
    // try {
    // instance.getValue();
    // } catch (ArrayIndexOutOfBoundsException ae) {
    // e = ae;
    // LOGGER.debug(ae.getLocalizedMessage());
    // }
    // assertNotNull(e);
    // }

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
