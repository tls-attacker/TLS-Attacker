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
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import java.util.LinkedList;
import java.util.List;

/**
 * This extension is defined in RFC7301
 */
public class AlpnExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableInteger alpnExtensionLength;
    @ModifiableVariableProperty
    private ModifiableByteArray alpnAnnouncedProtocols;

    @HoldsModifiableVariable
    private List<AlpnEntry> alpnEntryList;

    public AlpnExtensionMessage() {
        super(ExtensionType.ALPN);
        alpnEntryList = new LinkedList<>();
    }

    public AlpnExtensionMessage(Config config) {
        super(ExtensionType.ALPN);
        alpnEntryList = new LinkedList<>();
        for (String string : config.getAlpnAnnouncedProtocols()) {
            alpnEntryList.add(new AlpnEntry(string.getBytes()));
        }
    }

    public List<AlpnEntry> getAlpnEntryList() {
        return alpnEntryList;
    }

    public void setAlpnEntryList(List<AlpnEntry> alpnEntryList) {
        this.alpnEntryList = alpnEntryList;
    }

    public ModifiableInteger getAlpnExtensionLength() {
        return alpnExtensionLength;
    }

    public void setAlpnExtensionLength(ModifiableInteger alpnExtensionLength) {
        this.alpnExtensionLength = alpnExtensionLength;
    }

    public void setAlpnExtensionLength(int alpnExtensionLength) {
        this.alpnExtensionLength = ModifiableVariableFactory.safelySetValue(this.alpnExtensionLength,
                alpnExtensionLength);
    }

    public ModifiableByteArray getAlpnAnnouncedProtocols() {
        return alpnAnnouncedProtocols;
    }

    public void setAlpnAnnouncedProtocols(ModifiableByteArray alpnAnnouncedProtocols) {
        this.alpnAnnouncedProtocols = alpnAnnouncedProtocols;
    }

    public void setAlpnAnnouncedProtocols(byte[] alpnAnnouncedProtocols) {
        this.alpnAnnouncedProtocols = ModifiableVariableFactory.safelySetValue(this.alpnAnnouncedProtocols,
                alpnAnnouncedProtocols);
    }

}
