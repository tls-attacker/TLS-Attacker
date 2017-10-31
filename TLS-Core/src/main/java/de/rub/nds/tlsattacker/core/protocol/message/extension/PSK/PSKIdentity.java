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

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PSKIdentity {
    
    private ModifiableInteger identityLength;
    
    private ModifiableByteArray identity;
    private ModifiableByteArray obfuscatedTicketAge;
    
    public PSKIdentity(byte[] identity, byte[] obfuscatedTicketAge)
    {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
        this.identityLength = ModifiableVariableFactory.safelySetValue(identityLength, identity.length);
        this.obfuscatedTicketAge = ModifiableVariableFactory.safelySetValue(this.obfuscatedTicketAge, obfuscatedTicketAge);
    }
    
    public void setIdentity(ModifiableByteArray identity)
    {
        this.identity = identity;   
    }
    
    public byte[] getIdentity()
    {
        return identity.getValue();
    }
    
    public void setObfuscatedTicketAge(ModifiableByteArray obfuscatedTicketAge)
    {
        this.obfuscatedTicketAge = obfuscatedTicketAge;
    }
    
    public byte[] getObfuscatedTicketAge()
    {
        return obfuscatedTicketAge.getValue();
    }
    
    public int getIdentityLength()
    {
        return identityLength.getValue();
    }
    
    public void setIdentityLength(ModifiableInteger identityLength)
    {
        this.identityLength = identityLength;
    }
}
