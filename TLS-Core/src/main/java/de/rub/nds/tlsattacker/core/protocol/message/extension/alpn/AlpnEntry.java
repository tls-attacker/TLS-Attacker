/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.alpn;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.Serializable;

@XmlAccessorType(XmlAccessType.FIELD)
public class AlpnEntry extends ModifiableVariableHolder implements Serializable {

    private ModifiableInteger alpnEntryLength;

    private ModifiableString alpnEntry;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String alpnEntryConfig;

    public AlpnEntry() {}

    public AlpnEntry(String alpnEntryConfig) {
        this.alpnEntryConfig = alpnEntryConfig;
    }

    public ModifiableInteger getAlpnEntryLength() {
        return alpnEntryLength;
    }

    public void setAlpnEntryLength(ModifiableInteger alpnEntryLength) {
        this.alpnEntryLength = alpnEntryLength;
    }

    public void setAlpnEntryLength(int alpnEntryLength) {
        this.alpnEntryLength =
                ModifiableVariableFactory.safelySetValue(this.alpnEntryLength, alpnEntryLength);
    }

    public ModifiableString getAlpnEntry() {
        return alpnEntry;
    }

    public void setAlpnEntry(ModifiableString alpnEntry) {
        this.alpnEntry = alpnEntry;
    }

    public void setAlpnEntry(String alpnEntry) {
        this.alpnEntry = ModifiableVariableFactory.safelySetValue(this.alpnEntry, alpnEntry);
    }

    public String getAlpnEntryConfig() {
        return alpnEntryConfig;
    }

    public void setAlpnEntryConfig(String alpnEntryConfig) {
        this.alpnEntryConfig = alpnEntryConfig;
    }
}
