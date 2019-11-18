/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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

    @Test
    public void testSerialize() {
        PSKKeyExchangeModesExtensionMessage validMsg = new PSKKeyExchangeModesExtensionMessage();
        validMsg.setExtensionType(validMsg.getExtensionTypeConstant().getValue());
        validMsg.setExtensionLength(3);
        validMsg.setKeyExchangeModesListLength(2);
        validMsg.setKeyExchangeModesListBytes(new byte[] { 0, 1 });

        PSKKeyExchangeModesExtensionSerializer validSerializer = new PSKKeyExchangeModesExtensionSerializer(validMsg);
        byte[] serializedMsg = validSerializer.serialize();

        assertArrayEquals(new byte[] { 0, // extension_type
                                          // psk_key_exchange_modes(45), 2 bytes
                45, 0, // length of extension_data, 2 bytes
                3, 2, // extension_data: length of ke_modes
                0, // ke_modes[0]
                1 // ke_modes[1]
                }, serializedMsg);
    }
}