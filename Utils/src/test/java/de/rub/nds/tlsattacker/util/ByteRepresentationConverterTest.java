/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

/**
 *
 * @author Janis Fliegenschmidt - janis.fliegenschmidt@rub.de
 */
public class ByteRepresentationConverterTest {

    @Test
    public void hexStringToByteArray_SmokeTest() {
        byte[] result = ByteRepresentationConverter.hexStringToByteArray("1a2b");
        assertArrayEquals(new byte[] { (byte) 0x1a, (byte) 0x2b }, result);
    }

    /*
     * @Test(expected = IllegalArgumentException.class) public void
     * hexStringToByteArray_OddArgumentLength() {
     * ByteRepresentationConverter.hexStringToByteArray("12345"); }
     * 
     * @Test(expected = IllegalArgumentException.class) public void
     * hexStringToByteArray_IllegalCharacter() {
     * ByteRepresentationConverter.hexStringToByteArray("1g"); }
     */
}
