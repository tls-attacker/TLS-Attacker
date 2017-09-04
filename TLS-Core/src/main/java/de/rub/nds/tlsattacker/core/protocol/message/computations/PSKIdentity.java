/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import java.math.BigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
/**
 *
 * @author florian
 */
public class PSKIdentity extends KeyExchangeComputations{
    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.PSK_IDENTITY)
    private ModifiableByteArray identity;
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByteArray identity_length;
    
    public PSKIdentity(ModifiableByteArray identity_length, ModifiableByteArray identity) {
        this.identity_length= identity_length;
        this.identity = identity;
    }
    
    public PSKIdentity() {
    }
    
    public ModifiableByteArray getIdentity() {
        return identity;
    }
    
    public void setIdentity(ModifiableByteArray identity){
        this.identity=identity;
    }
    
    public void setIdentity(byte[] identity){
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }
    
    public ModifiableByteArray getIdentity_Lenght() {
        return identity_length;
    }
    
    public void setIdentitiy_lenght(ModifiableByteArray identity_length){
        this.identity_length=identity_length;
    }
    
    public void setIdentitiy_lenght(byte[] identity_length){
        this.identity_length=ModifiableVariableFactory.safelySetValue(this.identity_length, identity_length);
    }
}
