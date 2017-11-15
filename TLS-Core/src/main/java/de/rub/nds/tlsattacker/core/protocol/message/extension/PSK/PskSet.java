/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.PSK;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/** Contains (TLS 1.3) PSK-related values
 *
 * @author marcel
 */

@XmlAccessorType(XmlAccessType.FIELD)
public class PskSet implements Serializable {
    /**
     * PreSharedKeyIdentity to be used as PSK Identifier
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] preSharedKeyIdentity;

    /**
     * PreSharedKeys for PSK-Extension
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] preSharedKey;
    
    /**
     * TicketAge value to be used to generate the obfuscated ticket age for the given PSKs
     */
    private String ticketAge;
    
    /**
     * TicketAgeAdd value to be used to obfuscate the ticket age for the given PSKs
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] ticketAgeAdd;
    
    private CipherSuite cipherSuite;

    /**
     * @return the preSharedKeyIdentity
     */
    public byte[] getPreSharedKeyIdentity() {
        return preSharedKeyIdentity;
    }

    /**
     * @param preSharedKeyIdentity the preSharedKeyIdentity to set
     */
    public void setPreSharedKeyIdentity(byte[] preSharedKeyIdentity) {
        this.preSharedKeyIdentity = preSharedKeyIdentity;
    }

    /**
     * @return the preSharedKey
     */
    public byte[] getPreSharedKey() {
        return preSharedKey;
    }

    /**
     * @param preSharedKey the preSharedKey to set
     */
    public void setPreSharedKey(byte[] preSharedKey) {
        this.preSharedKey = preSharedKey;
    }

    /**
     * @return the ticketAge
     */
    public String getTicketAge() {
        return ticketAge;
    }

    /**
     * @param ticketAge the ticketAge to set
     */
    public void setTicketAge(String ticketAge) {
        this.ticketAge = ticketAge;
    }

    /**
     * @return the ticketAgeAdd
     */
    public byte[] getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    /**
     * @param ticketAgeAdd the ticketAgeAdd to set
     */
    public void setTicketAgeAdd(byte[] ticketAgeAdd) {
        this.ticketAgeAdd = ticketAgeAdd;
    }

    /**
     * @return the cipherSuite
     */
    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    /**
     * @param cipherSuite the cipherSuite to set
     */
    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }
}
