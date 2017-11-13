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
public class PSKBinder {
    
    private ModifiableInteger binderEntryLength;
    private ModifiableByteArray binderEntry;
    
    public PSKBinder(byte[] binderEntry)
    {
        this.binderEntry = ModifiableVariableFactory.safelySetValue(this.binderEntry, binderEntry);
        binderEntryLength = ModifiableVariableFactory.safelySetValue(binderEntryLength, binderEntry.length);
    }
    
    public void setBinderEntry(ModifiableByteArray binderEntry)
    {
        this.binderEntry = binderEntry;
    }
    
    public void setBinderEntry(byte[] binderEntry)
    {
        this.binderEntry = ModifiableVariableFactory.safelySetValue(this.binderEntry, binderEntry);
    }
    
    public byte[] getBinderEntry()
    {
        return binderEntry.getValue();
    }
    
    public void setBinderEntryLength(ModifiableInteger binderEntryLength)
    {
        this.binderEntryLength = binderEntryLength;
    }
    
    public int getBinderEntryLength()
    {
        return binderEntryLength.getValue();
    }
    
    
}
