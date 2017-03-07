/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.computations;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import java.io.Serializable;
import java.math.BigInteger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientComputations extends KeyExchangeComputations {

    /**
     * client's private key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger x;

    public DHClientComputations() {
    }

    public ModifiableBigInteger getX() {
        return x;
    }

    public void setX(ModifiableBigInteger x) {
        this.x = x;
    }

    public void setX(BigInteger x) {
        this.x = ModifiableVariableFactory.safelySetValue(this.x, x);
    }
}
