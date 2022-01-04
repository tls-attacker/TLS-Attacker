/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.KeyUpdateHandler;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "KeyUpdate")
public class KeyUpdateMessage extends HandshakeMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableByte requestMode;

    @Override
    public KeyUpdateHandler getHandler(TlsContext context) {
        return new KeyUpdateHandler(context);
    }

    public KeyUpdateMessage() {
        super(HandshakeMessageType.KEY_UPDATE);
        this.setIncludeInDigest(false);
    }

    public KeyUpdateMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.KEY_UPDATE);
        this.setIncludeInDigest(false);
    }

    public KeyUpdateMessage(Config tlsConfig, KeyUpdateRequest requestUpdate) {
        super(tlsConfig, HandshakeMessageType.KEY_UPDATE);
        setRequestMode(requestUpdate);
        this.setIncludeInDigest(false);
    }

    public final void setRequestMode(KeyUpdateRequest requestMode) {
        this.requestMode = ModifiableVariableFactory.safelySetValue(this.requestMode, requestMode.getValue());
    }

    public void setRequestMode(ModifiableByte requestMode) {
        this.requestMode = requestMode;
    }

    public ModifiableByte getRequestMode() {
        return this.requestMode;
    }

    @Override
    public String toShortString() {
        return "KU";
    }

}
