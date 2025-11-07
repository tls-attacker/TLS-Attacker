/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.handler.AckHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import de.rub.nds.tlsattacker.core.protocol.parser.AckParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AckPreperator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AckSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "Ack")
public class AckMessage extends ProtocolMessage {

    private List<RecordNumber> recordNumbers;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger recordNumberLength;

    public List<RecordNumber> getRecordNumbers() {
        return recordNumbers;
    }

    public void setRecordNumbers(List<RecordNumber> recordNumbers) {
        this.recordNumbers = recordNumbers;
    }

    public void setRecordNumberLength(ModifiableInteger recordNumberLength) {
        this.recordNumberLength = recordNumberLength;
    }

    public ModifiableInteger getRecordNumberLength() {
        return recordNumberLength;
    }

    public void setRecordNumberLength(int recordNumberLength) {
        this.recordNumberLength =
                ModifiableVariableFactory.safelySetValue(
                        this.recordNumberLength, recordNumberLength);
    }

    public AckMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.ACK;
    }

    @Override
    public String toCompactString() {
        return "ACK";
    }

    @Override
    public String toShortString() {
        return "ACK";
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ACK Message");
        sb.append("\t Acknowledged record numbers: \n");
        if (recordNumbers != null) {
            for (RecordNumber recordNumber : recordNumbers) {
                sb.append("\t - Epoch ").append(recordNumber.getEpoch().getValue());
                sb.append(" | SQN ").append(recordNumber.getSequenceNumber().getValue());
            }
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler<AckMessage> getHandler(Context context) {
        return new AckHandler(context);
    }

    @Override
    public ProtocolMessageSerializer<AckMessage> getSerializer(Context context) {
        return new AckSerializer(this);
    }

    @Override
    public ProtocolMessagePreparator<AckMessage> getPreparator(Context context) {
        return new AckPreperator(context.getChooser(), this, context.getTlsContext());
    }

    @Override
    public ProtocolMessageParser<AckMessage> getParser(Context tlsContext, InputStream stream) {
        return new AckParser(stream);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 61 * hash + Objects.hashCode(this.recordNumbers);
        hash = 61 * hash + Objects.hashCode(this.recordNumberLength);
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
        final AckMessage other = (AckMessage) obj;
        if (!Objects.equals(this.recordNumbers, other.recordNumbers)) {
            return false;
        }
        return Objects.equals(this.recordNumberLength, other.recordNumberLength);
    }
}
