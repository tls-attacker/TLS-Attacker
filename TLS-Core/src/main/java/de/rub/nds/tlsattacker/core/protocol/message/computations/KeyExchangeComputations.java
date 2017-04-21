/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class KeyExchangeComputations extends ModifiableVariableHolder implements Serializable {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray premasterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray clientRandom;

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

    public ModifiableByteArray getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(ModifiableByteArray clientRandom) {
        this.clientRandom = clientRandom;
    }

    public void setClientRandom(byte[] random) {
        this.clientRandom = ModifiableVariableFactory.safelySetValue(this.clientRandom, random);
    }
}
