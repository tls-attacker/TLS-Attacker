/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayInsertModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.TrippleVector;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author robert
 */
public class ShortPaddingGeneratorTest {

    private ShortPaddingGenerator generator;

    public ShortPaddingGeneratorTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        generator = new ShortPaddingGenerator();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testGetVectors() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                System.out.println(suite.name());
                generator.getVectors(suite, ProtocolVersion.TLS10);
                generator.getVectors(suite, ProtocolVersion.TLS11);
                generator.getVectors(suite, ProtocolVersion.TLS12);
            }
        }
    }

    /**
     * Test of createBasicMacVectors method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateBasicMacVectors() {
        List<PaddingVector> vectors = generator.createBasicMacVectors(CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12);
        assertEquals(3, vectors.size());
        int macSize = AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA).getSize();
        VariableModification modification = ((TrippleVector)vectors.get(0)).getCleanModification();
        ModifiableByteArray array = new ModifiableByteArray();
        array.setModification(modification);
        byte[] expectedPlain = new byte[ShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH - ShortPaddingGenerator.DEFAULT_PADDING_LENGTH - macSize];
        assertArrayEquals(expectedPlain, array.getValue());
    }

    /**
     * Test of createMissingMacByteVectors method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateMissingMacByteVectors() {
    }

    /**
     * Test of createOnlyPaddingVectors method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateOnlyPaddingVectors() {
    }

    /**
     * Test of createClassicModifiedPadding method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateClassicModifiedPadding() {
    }

    /**
     * Test of createFlippedModifications method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateFlippedModifications() {
        List<VariableModification> modifications = generator.createFlippedModifications(10);
        ModifiableByteArray array = new ModifiableByteArray();
        array.setOriginalValue(new byte[10]);
        byte[] expected = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        array.setModification(modifications.get(0));
        assertArrayEquals("Last byte should be xored with 0x01", expected, array.getValue());
        expected = new byte[]{0, 0, 0, 0, 0, 8, 0, 0, 0, 0};
        array.setModification(modifications.get(1));
        assertArrayEquals("Middle byte should be xored with 0x08", expected, array.getValue());
        expected = new byte[]{(byte) 128, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        array.setModification(modifications.get(2));
        assertArrayEquals("First byte should be xored with 0x80", expected, array.getValue());
    }

    /**
     * Test of createRecordsWithPlainData method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateRecordsWithPlainData() {
    }

    /**
     * Test of createVectorWithPlainData method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateVectorWithPlainData() {
    }

    /**
     * Test of createVectorWithModifiedPadding method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateVectorWithModifiedPadding() {
    }

    /**
     * Test of createVectorWithModifiedMac method, of class ShortPaddingGenerator.
     */
    @Test
    public void testCreateVectorWithModifiedMac() {
    }

}
