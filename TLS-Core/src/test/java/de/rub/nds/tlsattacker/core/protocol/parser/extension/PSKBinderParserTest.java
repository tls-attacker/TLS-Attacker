/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PSKBinderParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { 0,
            ArrayConverter.hexStringToByteArray("2034c8ead79d29168694fcbff00106f86005ddf0a6480ea86cf06d8440752b62f9"),
            32, ArrayConverter
                .hexStringToByteArray("34c8ead79d29168694fcbff00106f86005ddf0a6480ea86cf06d8440752b62f9") } });
    }

    private final int startPosition;
    private final byte[] pskBinderBytes;
    private final long pskBinderEntryLength;
    private final byte[] pskBinderEntry;
    private PSKBinderParser parser;
    private PSKBinder pskBinder;

    public PSKBinderParserTest(int startPosition, byte[] pskBinderBytes, int pskBinderEntryLength,
        byte[] pskBinderEntry) {

        this.startPosition = startPosition;
        this.pskBinderBytes = pskBinderBytes;
        this.pskBinderEntryLength = pskBinderEntryLength;
        this.pskBinderEntry = pskBinderEntry;
    }

    @Before
    public void setUp() {
        parser = new PSKBinderParser(startPosition, pskBinderBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        pskBinder = parser.parse();

        assertEquals(pskBinderEntryLength, (long) pskBinder.getBinderEntryLength().getValue());
        assertArrayEquals(pskBinderEntry, pskBinder.getBinderEntry().getValue());

    }

}
