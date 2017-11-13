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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
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
    
    private ModifiableInteger selectedIdentity;
    
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
        return binderListLength.getValue();
    }
    
    public void setBinderListLength(int binderListLength)
    {
        this.binderListLength = ModifiableVariableFactory.safelySetValue(this.binderListLength, binderListLength);
    }
    
    public void calcIdentityListLength()
    {
        int len = 0;
        for(PSKIdentity identity: identities)
        {
            len += identity.getIdentityLength() + ExtensionByteLength.TICKET_AGE_LENGTH + ExtensionByteLength.PSK_IDENTITY_LENGTH;
        }
        this.identityListLength = ModifiableVariableFactory.safelySetValue(this.identityListLength, len);
    }
    
    public void calcBinderListLength()
    {
        int len = 0;
        for(PSKBinder binder: binders)
        {
            len += binder.getBinderEntryLength() + ExtensionByteLength.PSK_BINDER_LENGTH;
        }
        this.binderListLength = ModifiableVariableFactory.safelySetValue(this.binderListLength, len);
    }

    /**
     * @return the selectedIdentity
     */
    public ModifiableInteger getSelectedIdentity() {
        return selectedIdentity;
    }

    /**
     * @param selectedIdentity the selectedIdentity to set
     */
    public void setSelectedIdentity(ModifiableInteger selectedIdentity) {
        this.selectedIdentity = selectedIdentity;
    }
    
    public void setSelectedIdentity(int selectedIdentity) {
        this.selectedIdentity = ModifiableVariableFactory.safelySetValue(this.selectedIdentity, selectedIdentity);
    }
    
    
}
