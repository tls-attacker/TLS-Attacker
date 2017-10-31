/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import java.util.List;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionMessage extends ExtensionMessage {
    
    private ModifiableInteger identityListLength;
    private ModifiableInteger binderListLength;
    
    @HoldsModifiableVariable
    private List<PSKIdentity> identities;
    @HoldsModifiableVariable
    private List<PSKBinder> binders;
    
    public PreSharedKeyExtensionMessage() {
        super(ExtensionType.PRE_SHARED_KEY);
    }
    
    public List<PSKIdentity> getIdentities()
    {
        return identities;
    }
    
    public void setIdentities(List<PSKIdentity> identities)
    {
        this.identities = identities;
    }
    
    public List<PSKBinder> getBinders()
    {
        return binders;
    }
    
    public void setBinders(List<PSKBinder> binders)
    {
        this.binders = binders;
    }
    
    public int getIdentityListLength()
    {
        return identityListLength.getValue();
    }
    
    public void setIdentityListLength(int identityListLength)
    {
        this.identityListLength = ModifiableVariableFactory.safelySetValue(this.identityListLength, identityListLength);
    }
    
    public int getBinderListLength()
    {
        return identityListLength.getValue();
    }
    
    public void setBinderListLength(int identityListLength)
    {
        this.identityListLength = ModifiableVariableFactory.safelySetValue(this.identityListLength, identityListLength);
    }
    
}
