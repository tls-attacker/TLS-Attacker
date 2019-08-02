/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.psk;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * Contains (TLS 1.3) PSK-related values
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
     * TicketAge value to be used to generate the obfuscated ticket age for the
     * given PSKs
     */
    private String ticketAge;

    /**
     * TicketAgeAdd value to be used to obfuscate the ticket age for the given
     * PSKs
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] ticketAgeAdd;

    private CipherSuite cipherSuite;

    public PskSet() {
    }

    public PskSet(byte[] preSharedKeyIdentity, byte[] preSharedKey, String ticketAge, byte[] ticketAgeAdd,
            CipherSuite cipherSuite) {
        this.preSharedKeyIdentity = preSharedKeyIdentity;
        this.preSharedKey = preSharedKey;
        this.ticketAge = ticketAge;
        this.ticketAgeAdd = ticketAgeAdd;
        this.cipherSuite = cipherSuite;
    }

    /**
     * @return the preSharedKeyIdentity
     */
    public byte[] getPreSharedKeyIdentity() {
        return preSharedKeyIdentity;
    }

    /**
     * @param preSharedKeyIdentity
     *            the preSharedKeyIdentity to set
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
     * @param preSharedKey
     *            the preSharedKey to set
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
     * @param ticketAge
     *            the ticketAge to set
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
     * @param ticketAgeAdd
     *            the ticketAgeAdd to set
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
     * @param cipherSuite
     *            the cipherSuite to set
     */
    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + Arrays.hashCode(this.preSharedKeyIdentity);
        hash = 43 * hash + Arrays.hashCode(this.preSharedKey);
        hash = 43 * hash + Objects.hashCode(this.ticketAge);
        hash = 43 * hash + Arrays.hashCode(this.ticketAgeAdd);
        hash = 43 * hash + Objects.hashCode(this.cipherSuite);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PskSet other = (PskSet) obj;
        if (!Objects.equals(this.ticketAge, other.ticketAge)) {
            return false;
        }
        if (!Arrays.equals(this.preSharedKeyIdentity, other.preSharedKeyIdentity)) {
            return false;
        }
        if (!Arrays.equals(this.preSharedKey, other.preSharedKey)) {
            return false;
        }
        if (!Arrays.equals(this.ticketAgeAdd, other.ticketAgeAdd)) {
            return false;
        }
        return this.cipherSuite == other.cipherSuite;
    }
}
