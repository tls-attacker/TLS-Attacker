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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import org.junit.jupiter.api.Test;

public class AlpnExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                AlpnExtensionMessage, AlpnExtensionSerializer, AlpnExtensionPreparator> {

    public AlpnExtensionPreparatorTest() {
        super(
                AlpnExtensionMessage::new,
                AlpnExtensionSerializer::new,
                AlpnExtensionPreparator::new);
        createNewMessageAndPreparator(false);
    }

    @Test
    @Override
    public void testPrepare() {
        String announcedProtocols = "h2";
        byte[] protocolsWithLength =
                ArrayConverter.concatenate(new byte[] {0x02}, announcedProtocols.getBytes());

        context.getConfig().setDefaultProposedAlpnProtocols(announcedProtocols);
        preparator.prepare();
        assertArrayEquals(ExtensionType.ALPN.getValue(), message.getExtensionType().getValue());
        assertEquals(3, message.getProposedAlpnProtocolsLength().getValue());
        assertArrayEquals(protocolsWithLength, message.getProposedAlpnProtocols().getValue());
    }
}
