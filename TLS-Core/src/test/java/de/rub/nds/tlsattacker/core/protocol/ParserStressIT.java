/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.ByteArrayInputStream;
import java.util.Random;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * This test makes sure that the parsers don't throw other exceptions other than parser exceptions
 * Not every message is always parsable, but the parser should be able to deal with everything
 */
public class ParserStressIT extends GenericParserSerializerTest {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testParser() {
        Random r = new Random(42);
        for (int i = 0; i < 10000; i++) {
            try {
                int length = r.nextInt(10000);
                byte[] bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                int start = r.nextInt(100);
                if (bytesToParse.length > start) {
                    bytesToParse[start] = 0x02;
                }
                ProtocolMessage randomMessage = getRandomMessage(r);
                ProtocolMessageParser parser =
                        randomMessage.getParser(
                                new TlsContext(), new ByteArrayInputStream(bytesToParse));
                parser.parse(randomMessage);
            } catch (EndOfStreamException | ParserException ignored) {
            }
        }
    }
}
