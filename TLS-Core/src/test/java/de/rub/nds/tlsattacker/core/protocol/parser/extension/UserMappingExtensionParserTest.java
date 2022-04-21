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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class UserMappingExtensionParserTest {

    private final byte[] extensionBytes = ArrayConverter.hexStringToByteArray("40");
    private final UserMappingExtensionHintType hintType = UserMappingExtensionHintType.UPN_DOMAIN_HINT;
    private UserMappingExtensionParser parser;
    private UserMappingExtensionMessage message;
    private final Config config = Config.createConfig();

    @Before
    public void setUp() {
        TlsContext tlsContext = new TlsContext(config);
        parser = new UserMappingExtensionParser(new ByteArrayInputStream(extensionBytes), tlsContext);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new UserMappingExtensionMessage();
        parser.parse(message);
        assertEquals(hintType.getValue(), (long) message.getUserMappingType().getValue());
    }
}
