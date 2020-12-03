/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;

import java.util.ArrayList;
import java.util.List;

public interface SendingAction {
    public abstract List<ProtocolMessage> getSendMessages();

    public abstract List<AbstractRecord> getSendRecords();

    public default List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        return new ArrayList<>();
    }

    public default List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        return new ArrayList<>();
    }
}
