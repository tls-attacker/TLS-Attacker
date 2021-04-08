/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.KeyUpdateHandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateMessage extends HandshakeMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyUpdateRequest requestUpdate;

    @Override
    public KeyUpdateHandler getHandler(TlsContext context) {
        return new KeyUpdateHandler(context);
    }

    public KeyUpdateMessage() {
        super(HandshakeMessageType.KEY_UPDATE);
        this.setIncludeInDigest(false);
        this.requestUpdate = KeyUpdateRequest.UPDATE_NOT_REQUESTED;
    }

    public KeyUpdateMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.KEY_UPDATE);
        this.requestUpdate = KeyUpdateRequest.UPDATE_NOT_REQUESTED;
        this.setIncludeInDigest(false);
    }

    public KeyUpdateMessage(HandshakeMessageType handshakeMessageType, KeyUpdateRequest requestUpdate) {
        super(handshakeMessageType);
        this.requestUpdate = requestUpdate;
        this.setIncludeInDigest(false);
    }

    public void setRequestUpdate(KeyUpdateRequest keyupdaterequest) {
        requestUpdate = keyupdaterequest;
    }

    public KeyUpdateRequest getRequestUpdate() {
        return this.requestUpdate;
    }

}
