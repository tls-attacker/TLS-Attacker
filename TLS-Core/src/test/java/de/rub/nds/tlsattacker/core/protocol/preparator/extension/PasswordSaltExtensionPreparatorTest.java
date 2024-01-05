/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import org.junit.jupiter.api.Test;

public class PasswordSaltExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                PasswordSaltExtensionMessage,
                PasswordSaltExtensionSerializer,
                PasswordSaltExtensionPreparator> {

    public PasswordSaltExtensionPreparatorTest() {
        super(
                PasswordSaltExtensionMessage::new,
                PasswordSaltExtensionSerializer::new,
                PasswordSaltExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        byte[] salt = ArrayConverter.hexStringToByteArray("00aaff");
        context.getConfig().setDefaultServerPWDSalt(salt);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.PASSWORD_SALT.getValue(), message.getExtensionType().getValue());
        assertEquals(5, message.getExtensionLength().getValue());
        assertArrayEquals(salt, message.getSalt().getValue());
    }
}
