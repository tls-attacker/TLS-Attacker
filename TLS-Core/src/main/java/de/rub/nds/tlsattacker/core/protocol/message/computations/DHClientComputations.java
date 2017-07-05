/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
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
