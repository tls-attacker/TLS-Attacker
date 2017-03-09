/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.serializer.RetransmitMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * 
 *         Raw bytes of a previos send message retransmitted
 */
public class RetransmitMessage extends ProtocolMessage {

    private byte[] bytesToTransmit;

    public RetransmitMessage(byte[] bytesToTransmit) {
        super();
        this.setRequired(false);
        protocolMessageType = ProtocolMessageType.UNKNOWN;
        this.bytesToTransmit = bytesToTransmit;
    }

    @Override
    public String toCompactString() {
        return "Retransmitted Message";
    }

    @Override
    public Serializer getSerializer() {
        return new RetransmitMessageSerializer(this);
    }

    public byte[] getBytesToTransmit() {
        return bytesToTransmit;
    }

    public void setBytesToTransmit(byte[] bytesToTransmit) {
        this.bytesToTransmit = bytesToTransmit;
    }

}
