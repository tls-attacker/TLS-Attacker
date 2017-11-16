/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.PSK;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

public class PSKIdentity {

    private ModifiableInteger identityLength;

    private ModifiableByteArray identity;
    private ModifiableByteArray obfuscatedTicketAge;

    public PSKIdentity() {

    }

    public void setIdentity(ModifiableByteArray identity) {
        this.identity = identity;
    }

    public void setIdentity(byte[] identity) {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }

    public ModifiableByteArray getIdentity() {
        return identity;
    }

    public void setObfuscatedTicketAge(ModifiableByteArray obfuscatedTicketAge) {
        this.obfuscatedTicketAge = obfuscatedTicketAge;
    }

    public void setObfuscatedTicketAge(byte[] obfuscatedTicketAge) {
        this.obfuscatedTicketAge = ModifiableVariableFactory.safelySetValue(this.obfuscatedTicketAge,
                obfuscatedTicketAge);
    }

    public ModifiableByteArray getObfuscatedTicketAge() {
        return obfuscatedTicketAge;
    }

    public ModifiableInteger getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableInteger identityLength) {
        this.identityLength = identityLength;
    }

    public void setIdentityLength(int identityLength) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }
}
