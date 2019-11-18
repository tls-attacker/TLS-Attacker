/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PasswordSaltExtensionPreparatorTest {

    private TlsContext context;
    private PasswordSaltExtensionMessage message;
    private PasswordSaltExtensionPreparator preparator;
    private byte[] salt = ArrayConverter.hexStringToByteArray("00aaff");

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PasswordSaltExtensionMessage();
        preparator = new PasswordSaltExtensionPreparator(context.getChooser(), message,
                new PasswordSaltExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setDefaultServerPWDSalt(salt);
        preparator.prepare();

        assertArrayEquals(ExtensionType.PASSWORD_SALT.getValue(), message.getExtensionType().getValue());
        assertEquals(3 + 2, (long) message.getExtensionLength().getValue());
        assertArrayEquals(salt, message.getSalt().getValue());

    }

}