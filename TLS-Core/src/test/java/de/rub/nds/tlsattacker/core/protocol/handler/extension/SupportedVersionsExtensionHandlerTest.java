/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import org.junit.jupiter.api.Test;

public class SupportedVersionsExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                SupportedVersionsExtensionMessage, SupportedVersionsExtensionHandler> {

    public SupportedVersionsExtensionHandlerTest() {
        super(SupportedVersionsExtensionMessage::new, SupportedVersionsExtensionHandler::new);
    }

    /** Test of adjustContext method, of class SupportedVersionsExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(
                ArrayConverter.concatenate(
                        ProtocolVersion.TLS12.getValue(), ProtocolVersion.TLS13.getValue()));
        handler.adjustTLSExtensionContext(msg);
        assertEquals(2, context.getClientSupportedProtocolVersions().size());
        assertEquals(
                context.getHighestClientProtocolVersion().getValue(),
                ProtocolVersion.TLS13.getValue());
    }

    @Test
    public void testadjustContextBadVersions() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(new byte[] {0, 1, 2, 3, 3, 3});
        handler.adjustTLSExtensionContext(msg);
        assertEquals(1, context.getClientSupportedProtocolVersions().size());
        assertEquals(
                context.getHighestClientProtocolVersion().getValue(),
                ProtocolVersion.TLS12.getValue());
    }
}
