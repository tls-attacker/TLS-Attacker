/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PasswordSaltExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PasswordSaltExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return PasswordSaltExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private final int saltLength;
    private final byte[] salt;
    private PasswordSaltExtensionSerializer serializer;
    private PasswordSaltExtensionMessage msg;

    public PasswordSaltExtensionSerializerTest(byte[] expectedBytes, int saltLength, byte[] salt) {
        this.expectedBytes = expectedBytes;
        this.saltLength = saltLength;
        this.salt = salt;
    }

    @Before
    public void setUp() {
        msg = new PasswordSaltExtensionMessage();
        serializer = new PasswordSaltExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setSalt(salt);
        msg.setSaltLength(saltLength);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}
