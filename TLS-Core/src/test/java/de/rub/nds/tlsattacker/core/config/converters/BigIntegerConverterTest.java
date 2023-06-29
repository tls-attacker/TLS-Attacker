/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.converters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.beust.jcommander.ParameterException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BigIntegerConverterTest {
    private BigIntegerConverter converter;

    @BeforeEach
    public void setUpClass() {
        converter = new BigIntegerConverter();
    }

    @Test
    public void testConvert() {
        String testString = "0";
        assertEquals(new BigInteger("0"), converter.convert(testString));
        testString = "0x1";
        assertEquals(new BigInteger("1"), converter.convert(testString));
        testString = Integer.toString(Integer.MAX_VALUE);
        assertEquals(
                new BigInteger(Integer.toString(Integer.MAX_VALUE)), converter.convert(testString));
        testString = "0xFFFFFFFFFFFFFFFF";
        assertEquals(new BigInteger("FFFFFFFFFFFFFFFF", 16), converter.convert(testString));
    }

    @Test
    public void testConvertError() {
        assertThrows(ParameterException.class, () -> converter.convert("hello world"));
    }
}
