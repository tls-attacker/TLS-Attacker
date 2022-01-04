/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParserTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ExtendedMasterSecretExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private ExtendedMasterSecretExtensionMessage message;

    public ExtendedMasterSecretExtensionSerializerTest(byte[] expectedBytes) {
        this.expectedBytes = expectedBytes;
    }

    @Test
    public void testSerializeExtensionContent() {
        message = new ExtendedMasterSecretExtensionMessage();
        ExtendedMasterSecretExtensionSerializer serializer = new ExtendedMasterSecretExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}
