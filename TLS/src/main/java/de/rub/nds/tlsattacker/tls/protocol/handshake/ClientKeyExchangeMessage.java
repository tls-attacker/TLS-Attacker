/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ClientKeyExchangeMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray premasterSecret;

    public ClientKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
    }

    public ModifiableByteArray getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] value) {
        this.masterSecret = ModifiableVariableFactory.safelySetValue(this.masterSecret, value);
    }

    public ModifiableByteArray getPremasterSecret() {
        return premasterSecret;
    }

    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
        this.premasterSecret = ModifiableVariableFactory.safelySetValue(this.premasterSecret, premasterSecret);
    }

}
