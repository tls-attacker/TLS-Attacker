/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.KeyUpdateHandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateMessage extends HandshakeMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private KeyUpdateRequest request_update;

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new KeyUpdateHandler(context);
    }

    public KeyUpdateMessage() {
        super(HandshakeMessageType.KEY_UPDATE);
        this.request_update = KeyUpdateRequest.UPDATE_REQUESTED;
    }

    public KeyUpdateMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.KEY_UPDATE);
        this.request_update = KeyUpdateRequest.UPDATE_REQUESTED;
    }

    public KeyUpdateMessage(HandshakeMessageType handshakeMessageType, KeyUpdateRequest request_update) {
        super(handshakeMessageType);
        this.request_update = request_update;
    }

    public void setRequestUpdate(int keyupdaterequest) {
        if (keyupdaterequest == 1) {
            request_update = KeyUpdateRequest.UPDATE_REQUESTED;
        } else
            request_update = KeyUpdateRequest.UPDATE_NOT_REQUESTED;
    }

    public void setRequestUpdate(KeyUpdateRequest keyupdaterequest) {
        request_update = KeyUpdateRequest.UPDATE_REQUESTED;
    }

    public KeyUpdateRequest getRequestUpdate() {
        return this.request_update;
    }

}
