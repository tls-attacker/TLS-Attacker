/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * 
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.ParameterException;
import java.math.BigInteger;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class BigIntegerConverterTest {
    private BigIntegerConverter converter;

    @Before
    public void setUp() {
        converter = new BigIntegerConverter();
    }

    @Test
    public void testConvert() {
        String testString = "0";
        assertEquals(new BigInteger("0"), converter.convert(testString));
        testString = "0x1";
        assertEquals(new BigInteger("1"), converter.convert(testString));
        testString = Integer.toString(Integer.MAX_VALUE);
        assertEquals(new BigInteger(Integer.toString(Integer.MAX_VALUE)), converter.convert(testString));
        testString = "0xFFFFFFFFFFFFFFFF";
        assertEquals(new BigInteger("FFFFFFFFFFFFFFFF", 16), converter.convert(testString));
    }

    @Test(expected = ParameterException.class)
    public void testConvertError() {
        converter.convert("hello world");
    }
}
