/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.PSK;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

/**
 *
 * @author marcel
 */
public class PSKIdentity {
    private ModifiableByteArray identity;
    private ModifiableByteArray obfuscatedTicketAge;
    
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
    
}
