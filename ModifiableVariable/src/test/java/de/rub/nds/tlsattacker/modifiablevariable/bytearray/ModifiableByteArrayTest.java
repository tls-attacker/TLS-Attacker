/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Assume;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableByteArrayTest {

    private ModifiableByteArray start;

    private byte[] originalValue;

    private byte[] modification1;

    private byte[] modification2;

    private static final Logger LOGGER = LogManager.getLogger(ModifiableByteArray.class);

    @Before
    public void setUp() {
        originalValue = new byte[]{(byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6};
        modification1 = new byte[]{(byte) 2, (byte) 3};
        modification2 = new byte[]{(byte) 2, (byte) 1, (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5,
            (byte) 6};
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
    }

    /**
     * Test of setValue method, of class ModifiableByteArray.
     */
    @Test
    public void testSetValue() {
        LOGGER.info("testSetValue");
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
            expResult[first + i] = (byte) (originalValue[first + i] ^ modification1[i]);
        }

        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(modification1, first);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
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
        LOGGER.info("testPrepend");
        int len = originalValue.length + modification1.length;
        byte[] expResult = new byte[len];
        for (int i = 0; i < len; i++) {
            if (i < modification1.length) {
                expResult[i] = modification1[i];
            } else {
                expResult[i] = originalValue[i - modification1.length];
            }
        }

        VariableModification<byte[]> modifier = ByteArrayModificationFactory.insert(modification1, 0);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());
    }

    /**
     * Test of setAppendBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testAppendBytes() {
        LOGGER.info("testAppendBytes");
        int len = originalValue.length + modification1.length;
        byte[] expResult = new byte[len];
        for (int i = 0; i < len; i++) {
            if (i < originalValue.length) {
                expResult[i] = originalValue[i];
            } else {
                expResult[i] = modification1[i - originalValue.length];
            }
        }

        VariableModification<byte[]> modifier = ByteArrayModificationFactory
                .insert(modification1, originalValue.length);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());
    }

    /**
     * Test of setDeleteLastBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testDeleteLastBytes() {
        LOGGER.info("testDeleteLastBytes");
        // Löscht modification lenght viele bytes
        Assume.assumeTrue(modification1.length < originalValue.length);
        int len = originalValue.length - modification1.length;
        byte[] expResult = new byte[len];
        for (int i = 0; i < len; i++) {
            expResult[i] = originalValue[i];

        }
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.delete(len, modification1.length);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());

    }

    /**
     * Test of setDeleteFirstBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testDeleteFirstBytes() {
        LOGGER.info("testDeleteFirstBytes");
        // Löscht modification lenght viele bytes
        Assume.assumeTrue(modification1.length < originalValue.length);

        int len = originalValue.length;
        byte[] expResult = new byte[len - modification1.length];
        for (int i = modification1.length; i < len; i++) {
            expResult[i - modification1.length] = originalValue[i];

        }
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.delete(0, modification1.length);
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());

    }

    /**
     * Test of setDeleteBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testDeleteBytes() {
        LOGGER.info("testDeleteBytes");
        // versucht randcases abzudecken
        LOGGER.debug("Testing Delete all Bytes");
        int len = originalValue.length;
        byte[] expResult = new byte[0];

        VariableModification<byte[]> modifier = ByteArrayModificationFactory.delete(0, len);
        start.setModification(modifier);

        assertArrayEquals(expResult, start.getValue());
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Testing Delete more Bytes than possible");
        modifier = ByteArrayModificationFactory.delete(0, len + 1);
        start.setModification(modifier);

        Exception e = null;
        try {
            start.getValue();
        } catch (ArrayIndexOutOfBoundsException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Testing Delete negative amount");
        modifier = ByteArrayModificationFactory.delete(0, -1);
        start.setModification(modifier);
        e = null;
        try {
            start.getValue();
        } catch (IllegalArgumentException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Testing Delete 0 Bytes");
        modifier = ByteArrayModificationFactory.delete(0, 0);
        start.setModification(modifier);
        e = null;
        try {
            start.getValue();
        } catch (IllegalArgumentException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Testing Delete from negative Start position");
        modifier = ByteArrayModificationFactory.delete(len * -2, modification1.length);
        start.setModification(modifier);

        e = null;
        try {
            start.getValue();
        } catch (Exception ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Testing Delete from to big Start Position");
        modifier = ByteArrayModificationFactory.delete(len * 2, modification1.length);
        start.setModification(modifier);

        e = null;
        try {
            start.getValue();
        } catch (ArrayIndexOutOfBoundsException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);

    }

    /**
     * Test of setInsertBytes method, of class ModifiableByteArray.
     */
    @Test
    public void testInsertBytes() {
        LOGGER.info("testInsertBytes");
        // Insert negativ position, insert 0 bytes, insert zu weit
        Assume.assumeTrue(modification1.length < originalValue.length);
        LOGGER.debug("Inserting negative Position");
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.insert(modification1, -2
                * originalValue.length);
        start.setModification(modifier);
        Exception e = null;
        try {
            start.getValue();
        } catch (IllegalArgumentException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);
        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Inserting empty Array");
        byte[] emptyArray = new byte[0];
        modifier = ByteArrayModificationFactory.insert(emptyArray, 0);
        start.setModification(modifier);
        assertArrayEquals(originalValue, start.getValue());

        start = new ModifiableByteArray();
        start.setOriginalValue(originalValue);
        LOGGER.debug("Inserting to big Start position");
        modifier = ByteArrayModificationFactory.insert(modification1, originalValue.length * 2);
        start.setModification(modifier);

        e = null;
        try {
            start.getValue();
        } catch (ArrayIndexOutOfBoundsException ae) {
            e = ae;
            LOGGER.debug(ae.getLocalizedMessage());
        }
        assertNotNull(e);

    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testIsOriginalValueModified() {
        assertFalse(start.isOriginalValueModified());
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[]{}, 0);
        start.setModification(modifier);
        assertFalse(start.isOriginalValueModified());
        modifier = ByteArrayModificationFactory.xor(new byte[]{1}, 0);
        start.setModification(modifier);
        assertTrue(start.isOriginalValueModified());
        modifier = ByteArrayModificationFactory.xor(new byte[]{0, 0}, originalValue.length - 2);
        start.setModification(modifier);
        assertFalse(start.isOriginalValueModified());
    }

    @Test
    public void testDuplicateModification() {
        LOGGER.info("testDuplicateModification");
        byte[] expResult = ArrayConverter.concatenate(originalValue, originalValue);

        VariableModification<byte[]> modifier = ByteArrayModificationFactory.duplicate();
        start.setModification(modifier);

        LOGGER.debug("Expected: " + ArrayConverter.bytesToHexString(expResult));
        LOGGER.debug("Computed: " + ArrayConverter.bytesToHexString(start.getValue()));
        assertArrayEquals(expResult, start.getValue());
    }

    /**
     * Test of explicitValue from file method
     */
    @Test
    public void testExplicitValueFromFile() {
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValueFromFile(0);
        start.setModification(modifier);
        byte[] expectedResult = new byte[0];
        byte[] result = start.getValue();
        assertArrayEquals(expectedResult, result);

        modifier = ByteArrayModificationFactory.explicitValueFromFile(1);
        start.setModification(modifier);
        expectedResult = new byte[]{00};
        result = start.getValue();
        assertArrayEquals(expectedResult, result);

        modifier = ByteArrayModificationFactory.explicitValueFromFile(17);
        start.setModification(modifier);
        expectedResult = new byte[]{(byte) 255};
        result = start.getValue();
        assertArrayEquals(expectedResult, result);
    }

    /**
     * Test Shuffle
     */
    @Test
    public void testShuffle() {
        LOGGER.info("testShuffle");
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.shuffle(new byte[]{0, 1});
        start.setModification(modifier);
        byte[] result = {1, 0, 2, 3, 4, 5, 6};
        assertArrayEquals(result, start.getValue());

        modifier = ByteArrayModificationFactory.shuffle(new byte[]{0, 1, 2, 3, 4, 5, 6});
        start.setModification(modifier);
        result = new byte[]{1, 0, 3, 2, 5, 4, 6};
        assertArrayEquals(result, start.getValue());
        
        modifier = ByteArrayModificationFactory.shuffle(new byte[]{0, 1, 2, 3, 4, 5, 6, 7});
        start.setModification(modifier);
        result = new byte[]{6, 0, 3, 2, 5, 4, 1};
        assertArrayEquals(result, start.getValue());
    }
}
