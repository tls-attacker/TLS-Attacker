/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.psk;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.FIELD)
public class PSKIdentity implements Serializable {

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] identityConfig;

    private String ticketAgeConfig;
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] ticketAgeAddConfig;

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

    /**
     * @return the identityConfig
     */
    public byte[] getIdentityConfig() {
        return identityConfig;
    }

    /**
     * @param identityConfig
     *            the identityConfig to set
     */
    public void setIdentityConfig(byte[] identityConfig) {
        this.identityConfig = identityConfig;
    }

    /**
     * @return the ticketAgeConfig
     */
    public String getTicketAgeConfig() {
        return ticketAgeConfig;
    }

    /**
     * @param ticketAgeConfig
     *            the ticketAgeConfig to set
     */
    public void setTicketAgeConfig(String ticketAgeConfig) {
        this.ticketAgeConfig = ticketAgeConfig;
    }

    /**
     * @return the ticketAgeAddConfig
     */
    public byte[] getTicketAgeAddConfig() {
        return ticketAgeAddConfig;
    }

    /**
     * @param ticketAgeAddConfig
     *            the ticketAgeAddConfig to set
     */
    public void setTicketAgeAddConfig(byte[] ticketAgeAddConfig) {
        this.ticketAgeAddConfig = ticketAgeAddConfig;
    }
}
