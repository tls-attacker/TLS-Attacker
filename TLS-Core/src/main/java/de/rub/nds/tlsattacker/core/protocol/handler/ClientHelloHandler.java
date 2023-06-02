/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;

public class ClientHelloHandler extends CoreClientHelloHandler<ClientHelloMessage> {
    public ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ClientHelloMessage message) {
        tlsContext.setLastClientHello(message.getCompleteResultingMessage().getValue());
        tlsContext.setInnerClientHello(message);
        super.adjustContext(message);
        LOGGER.debug(
                "Set InnerClient in Context to "
                        + ArrayConverter.bytesToHexString(message.getCompleteResultingMessage()));
    }

    @Override
    public void adjustContextAfterSerialize(ClientHelloMessage message) {
        super.adjustContextAfterSerialize(message);
        // dont overwrite last client hello if innerclienthello
        if (tlsContext.getInnerClientHello() == null) {
            tlsContext.setLastClientHello(message.getCompleteResultingMessage().getValue());
        }
    }
}
