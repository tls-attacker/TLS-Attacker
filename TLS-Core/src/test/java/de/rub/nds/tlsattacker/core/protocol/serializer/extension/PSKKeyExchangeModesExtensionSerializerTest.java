/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import static org.junit.Assert.*;
import org.junit.Test;

public class PSKKeyExchangeModesExtensionSerializerTest {

    @Test
    public void testSerializeExtensionContent() {

        PSKKeyExchangeModesExtensionMessage validMsg = new PSKKeyExchangeModesExtensionMessage();
        validMsg.setKeyExchangeModesListLength(2);
        validMsg.setKeyExchangeModesListBytes(new byte[] { 1, 0 });

        assertArrayEquals(new byte[] { 2, 1, 0 },
            new PSKKeyExchangeModesExtensionSerializer(validMsg).serializeExtensionContent());

        PSKKeyExchangeModesExtensionMessage invalidEmptyMsg = new PSKKeyExchangeModesExtensionMessage();
        invalidEmptyMsg.setKeyExchangeModesListLength(0);
        invalidEmptyMsg.setKeyExchangeModesListBytes(new byte[0]);

        assertArrayEquals(new byte[] { 0 },
            new PSKKeyExchangeModesExtensionSerializer(invalidEmptyMsg).serializeExtensionContent());
    }
}