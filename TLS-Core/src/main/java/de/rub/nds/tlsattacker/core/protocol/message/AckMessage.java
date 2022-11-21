/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.handler.AckHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.AckParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AckPreperator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AckSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.math.BigInteger;

@XmlRootElement(name = "ACK")
public class AckMessage extends ProtocolMessage<AckMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableByteArray recordNumbers;

    private ModifiableInteger recordNumberLength;

    public ModifiableByteArray getRecordNumbers() {
        return recordNumbers;
    }

    public void setRecordNumbers(byte[] recordNumbers) {
        this.recordNumbers =
                ModifiableVariableFactory.safelySetValue(this.recordNumbers, recordNumbers);
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
        sb.append("\t acknowledged record numbers:");
        byte[] recordNumberBytes = recordNumbers.getValue();
        for (int cursor = 0;
                cursor < recordNumberBytes.length;
                cursor += AckByteLength.RECORD_NUMBER_LENGTH) {
            BigInteger epoch =
                    new BigInteger(
                            recordNumberBytes, cursor, AckByteLength.RECORD_NUMBER_EPOCH_LENGTH);
            BigInteger seqNum =
                    new BigInteger(
                            recordNumberBytes,
                            cursor + AckByteLength.RECORD_NUMBER_EPOCH_LENGTH,
                            AckByteLength.RECORD_NUMBER_SEQUENCE_NUMBER_LENGTH);
            sb.append(" - Epoch ").append(epoch).append(" | SQN ").append(seqNum);
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler<AckMessage> getHandler(TlsContext tlsContext) {
        return new AckHandler(tlsContext);
    }

    @Override
    public ProtocolMessageSerializer<AckMessage> getSerializer(TlsContext tlsContext) {
        return new AckSerializer(this);
    }

    @Override
    public ProtocolMessagePreparator<AckMessage> getPreparator(TlsContext tlsContext) {
        return new AckPreperator(tlsContext.getChooser(), this, tlsContext);
    }

    @Override
    public ProtocolMessageParser<AckMessage> getParser(TlsContext tlsContext, InputStream stream) {
        return new AckParser(stream);
    }
}
