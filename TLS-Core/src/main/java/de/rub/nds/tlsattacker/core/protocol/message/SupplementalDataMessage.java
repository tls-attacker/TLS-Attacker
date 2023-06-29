/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.SupplementalDataHandler;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.SupplementalDataParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SupplementalDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SupplementalDataSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "SupplementalData")
public class SupplementalDataMessage extends HandshakeMessage<SupplementalDataMessage> {

    @HoldsModifiableVariable private List<SupplementalDataEntry> entries;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supplementalDataLength;

    @ModifiableVariableProperty private ModifiableByteArray supplementalDataBytes;

    public SupplementalDataMessage(Config config, LinkedList<SupplementalDataEntry> entries) {
        super(HandshakeMessageType.SUPPLEMENTAL_DATA);
        this.entries = new LinkedList<>(entries);
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
        this.supplementalDataLength =
                ModifiableVariableFactory.safelySetValue(
                        this.supplementalDataLength, supplementalDataLength);
    }

    public ModifiableByteArray getSupplementalDataBytes() {
        return supplementalDataBytes;
    }

    public void setSupplementalDataBytes(ModifiableByteArray supplementalDataBytes) {
        this.supplementalDataBytes = supplementalDataBytes;
    }

    public void setSupplementalDataBytes(byte[] supplementalDataBytes) {
        this.supplementalDataBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.supplementalDataBytes, supplementalDataBytes);
    }

    @Override
    public SupplementalDataHandler getHandler(TlsContext tlsContext) {
        return new SupplementalDataHandler(tlsContext);
    }

    @Override
    public SupplementalDataParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SupplementalDataParser(stream, tlsContext);
    }

    @Override
    public SupplementalDataPreparator getPreparator(TlsContext tlsContext) {
        return new SupplementalDataPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SupplementalDataSerializer getSerializer(TlsContext tlsContext) {
        return new SupplementalDataSerializer(this);
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
                sb.append("\n   Supplemental Data Type: ")
                        .append(entry.getSupplementalDataEntryType().getValue());
                sb.append("\n   Supplemental Data Length: ")
                        .append(entry.getSupplementalDataEntryLength().getValue());
                sb.append("\n   Supplemental Data : ")
                        .append(
                                ArrayConverter.bytesToHexString(
                                        entry.getSupplementalDataEntry().getValue()));
            }
        } else {
            sb.append("null");
        }

        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SDM";
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 29 * hash + Objects.hashCode(this.entries);
        hash = 29 * hash + Objects.hashCode(this.supplementalDataLength);
        hash = 29 * hash + Objects.hashCode(this.supplementalDataBytes);
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
        final SupplementalDataMessage other = (SupplementalDataMessage) obj;
        if (!Objects.equals(this.entries, other.entries)) {
            return false;
        }
        if (!Objects.equals(this.supplementalDataLength, other.supplementalDataLength)) {
            return false;
        }
        return Objects.equals(this.supplementalDataBytes, other.supplementalDataBytes);
    }
}
