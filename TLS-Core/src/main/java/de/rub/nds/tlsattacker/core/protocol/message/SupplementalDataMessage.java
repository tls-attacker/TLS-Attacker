/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.SupplementalDataHandler;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SupplementalDataMessage extends HandshakeMessage {

    @HoldsModifiableVariable
    private List<SupplementalDataEntry> entries;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supplementalDataLength;

    @ModifiableVariableProperty
    private ModifiableByteArray supplementalDataBytes;

    public SupplementalDataMessage(Config config, LinkedList<SupplementalDataEntry> entries) {
        super(HandshakeMessageType.SUPPLEMENTAL_DATA);
        this.entries = new LinkedList<>(entries);
    }

    public SupplementalDataMessage(Config config) {
        this();
    }

    public SupplementalDataMessage() {
        super(HandshakeMessageType.SUPPLEMENTAL_DATA);
        this.entries = new LinkedList<>();
    }

    public List<SupplementalDataEntry> getEntries() {
        return entries;
    }

    public void setEntries(List<SupplementalDataEntry> entries) {
        this.entries = entries;
    }

    public ModifiableInteger getSupplementalDataLength() {
        return supplementalDataLength;
    }

    public void setSupplementalDataLength(ModifiableInteger supplementalDataLength) {
        this.supplementalDataLength = supplementalDataLength;
    }

    public void setSupplementalDataLength(int supplementalDataLength) {
        this.supplementalDataLength = ModifiableVariableFactory.safelySetValue(this.supplementalDataLength,
                supplementalDataLength);
    }

    public ModifiableByteArray getSupplementalDataBytes() {
        return supplementalDataBytes;
    }

    public void setSupplementalDataBytes(ModifiableByteArray supplementalDataBytes) {
        this.supplementalDataBytes = supplementalDataBytes;
    }

    public void setSupplementalDataBytes(byte[] supplementalDataBytes) {
        this.supplementalDataBytes = ModifiableVariableFactory.safelySetValue(this.supplementalDataBytes,
                supplementalDataBytes);
    }

    @Override
    public SupplementalDataHandler getHandler(TlsContext context) {
        return new SupplementalDataHandler(context);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SupplementalDataMessage:");
        sb.append("\n  Supplemental Data Length: ");
        if (supplementalDataLength != null && supplementalDataLength.getValue() != null) {
            sb.append(supplementalDataLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  SupplementalDataEntries:\n");
        if (!entries.isEmpty()) {
            for (SupplementalDataEntry entry : entries) {
                sb.append("\n   Supplemental Data Type: ").append(entry.getSupplementalDataEntryType().getValue());
                sb.append("\n   Supplemental Data Length: ").append(entry.getSupplementalDataEntryLength().getValue());
                sb.append("\n   Supplemental Data : ").append(
                        ArrayConverter.bytesToHexString(entry.getSupplementalDataEntry().getValue()));
            }
        } else {
            sb.append("null");
        }

        return sb.toString();
    }

}
