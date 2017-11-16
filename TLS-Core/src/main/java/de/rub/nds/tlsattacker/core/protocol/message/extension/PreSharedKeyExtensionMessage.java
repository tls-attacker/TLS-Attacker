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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import java.util.List;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PreSharedKeyExtensionMessage extends ExtensionMessage {

    private ModifiableInteger identityListLength;
    private ModifiableInteger binderListLength;

    private ModifiableByteArray identityListBytes;
    private ModifiableByteArray binderListBytes;

    @HoldsModifiableVariable
    private List<PSKIdentity> identities;
    @HoldsModifiableVariable
    private List<PSKBinder> binders;

    private ModifiableInteger selectedIdentity;

    public PreSharedKeyExtensionMessage() {
        super(ExtensionType.PRE_SHARED_KEY);
    }

    public List<PSKIdentity> getIdentities() {
        return identities;
    }

    public void setIdentities(List<PSKIdentity> identities) {
        this.identities = identities;
    }

    public List<PSKBinder> getBinders() {
        return binders;
    }

    public void setBinders(List<PSKBinder> binders) {
        this.binders = binders;
    }

    public ModifiableInteger getIdentityListLength() {
        return identityListLength;
    }

    public void setIdentityListLength(int identityListLength) {
        this.identityListLength = ModifiableVariableFactory.safelySetValue(this.identityListLength, identityListLength);
    }

    public void setIdentityListLength(ModifiableInteger identityListLength) {
        this.identityListLength = identityListLength;
    }

    public ModifiableInteger getBinderListLength() {
        return binderListLength;
    }

    public void setBinderListLength(int binderListLength) {
        this.binderListLength = ModifiableVariableFactory.safelySetValue(this.binderListLength, binderListLength);
    }

    public void setBinderListLength(ModifiableInteger binderListLength) {
        this.binderListLength = binderListLength;
    }

    /**
     * @return the selectedIdentity
     */
    public ModifiableInteger getSelectedIdentity() {
        return selectedIdentity;
    }

    /**
     * @param selectedIdentity
     *            the selectedIdentity to set
     */
    public void setSelectedIdentity(ModifiableInteger selectedIdentity) {
        this.selectedIdentity = selectedIdentity;
    }

    public void setSelectedIdentity(int selectedIdentity) {
        this.selectedIdentity = ModifiableVariableFactory.safelySetValue(this.selectedIdentity, selectedIdentity);
    }

    /**
     * @return the identityListBytes
     */
    public ModifiableByteArray getIdentityListBytes() {
        return identityListBytes;
    }

    /**
     * @param identityListBytes
     *            the identityListBytes to set
     */
    public void setIdentityListBytes(ModifiableByteArray identityListBytes) {
        this.identityListBytes = identityListBytes;
    }

    public void setIdentityListBytes(byte[] identityListBytes) {
        this.identityListBytes = ModifiableVariableFactory.safelySetValue(this.identityListBytes, identityListBytes);
    }

    /**
     * @return the binderListBytes
     */
    public ModifiableByteArray getBinderListBytes() {
        return binderListBytes;
    }

    /**
     * @param binderListBytes
     *            the binderListBytes to set
     */
    public void setBinderListBytes(ModifiableByteArray binderListBytes) {
        this.binderListBytes = binderListBytes;
    }

    public void setBinderListBytes(byte[] binderListBytes) {
        this.binderListBytes = ModifiableVariableFactory.safelySetValue(this.binderListBytes, binderListBytes);
    }
}
