/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

public class SessionTicket extends ModifiableVariableHolder implements Serializable {
    @ModifiableVariableProperty()
    private ModifiableByteArray keyName;

    @ModifiableVariableProperty()
    private ModifiableByteArray iv;

    @ModifiableVariableProperty()
    private ModifiableByteArray encryptedState;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray mac;

    @ModifiableVariableProperty()
    private ModifiableByteArray identity;

    @ModifiableVariableProperty()
    private ModifiableByteArray ticketAgeAdd;

    @ModifiableVariableProperty()
    private ModifiableByteArray ticketNonce;

    @ModifiableVariableProperty()
    private ModifiableInteger identityLength;

    @ModifiableVariableProperty()
    private ModifiableInteger ticketNonceLength;

    public SessionTicket() {
    }

    public ModifiableByteArray getKeyName() {
        return keyName;
    }

    public void setKeyName(ModifiableByteArray keyName) {
        this.keyName = keyName;
    }

    public void setKeyName(byte[] keyName) {
        this.keyName = ModifiableVariableFactory.safelySetValue(this.keyName, keyName);
    }

    public ModifiableByteArray getIV() {
        return iv;
    }

    public void setIV(ModifiableByteArray iv) {
        this.iv = iv;
    }

    public void setIV(byte[] iv) {
        this.iv = ModifiableVariableFactory.safelySetValue(this.iv, iv);
    }

    public ModifiableByteArray getEncryptedState() {
        return encryptedState;
    }

    public void setEncryptedState(ModifiableByteArray encryptedState) {
        this.encryptedState = encryptedState;
    }

    public void setEncryptedState(byte[] encryptedState) {
        this.encryptedState = ModifiableVariableFactory.safelySetValue(this.encryptedState, encryptedState);
    }

    public ModifiableByteArray getMAC() {
        return mac;
    }

    public void setMAC(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void setMAC(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n    KeyName: ");
        if (keyName != null) {
            sb.append(ArrayConverter.bytesToHexString(keyName.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    IV: ");
        if (iv != null) {
            sb.append(ArrayConverter.bytesToHexString(iv.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    EncryptedState: ");
        if (encryptedState != null) {
            sb.append(ArrayConverter.bytesToHexString(encryptedState.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    MAC: ");
        if (mac != null) {
            sb.append(ArrayConverter.bytesToHexString(mac.getValue()));
        } else {
            sb.append("null");
        }
        if (identity != null) {
            sb.append("\n    Identity: ");
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        }
        return sb.toString();
    }

    /**
     * @return the identity
     */
    public ModifiableByteArray getIdentity() {
        return identity;
    }

    /**
     * @param identity
     *            the identity to set
     */
    public void setIdentity(ModifiableByteArray identity) {
        this.identity = identity;
    }

    /**
     * @param identity
     *            the identity to set
     */
    public void setIdentity(byte[] identity) {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }

    /**
     * @return the ticketAgeAdd
     */
    public ModifiableByteArray getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    /**
     * @param ticketAgeAdd
     *            the ticketAgeAdd to set
     */
    public void setTicketAgeAdd(ModifiableByteArray ticketAgeAdd) {
        this.ticketAgeAdd = ticketAgeAdd;
    }

    /**
     * @param ticketAgeAdd
     *            the ticketAgeAdd to set
     */
    public void setTicketAgeAdd(byte[] ticketAgeAdd) {
        this.ticketAgeAdd = ModifiableVariableFactory.safelySetValue(this.ticketAgeAdd, ticketAgeAdd);
    }

    /**
     * @return the ticketNonce
     */
    public ModifiableByteArray getTicketNonce() {
        return ticketNonce;
    }

    /**
     * @param ticketNonce
     *            the ticketNonce to set
     */
    public void setTicketNonce(ModifiableByteArray ticketNonce) {
        this.ticketNonce = ticketNonce;
    }

    /**
     * @param ticketNonce
     *            the ticketNonce to set
     */
    public void setTicketNonce(byte[] ticketNonce) {
        this.ticketNonce = ModifiableVariableFactory.safelySetValue(this.ticketNonce, ticketNonce);
    }

    /**
     * @return the identityLength
     */
    public ModifiableInteger getIdentityLength() {
        return identityLength;
    }

    /**
     * @param identityLength
     *            the identityLength to set
     */
    public void setIdentityLength(ModifiableInteger identityLength) {
        this.identityLength = identityLength;
    }

    /**
     * @param identityLength
     *            the identityLength to set
     */
    public void setIdentityLength(int identityLength) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }

    /**
     * @return the ticketNonceLength
     */
    public ModifiableInteger getTicketNonceLength() {
        return ticketNonceLength;
    }

    /**
     * @param ticketNonceLength
     *            the ticketNonceLength to set
     */
    public void setTicketNonceLength(ModifiableInteger ticketNonceLength) {
        this.ticketNonceLength = ticketNonceLength;
    }

    /**
     * @param ticketNonceLength
     *            the ticketNonceLength to set
     */
    public void setTicketNonceLength(int ticketNonceLength) {
        this.ticketNonceLength = ModifiableVariableFactory.safelySetValue(this.ticketNonceLength, ticketNonceLength);
    }
}