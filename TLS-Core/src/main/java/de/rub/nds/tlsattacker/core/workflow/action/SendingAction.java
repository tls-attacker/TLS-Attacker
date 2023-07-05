/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.ArrayList;
import java.util.List;

public interface SendingAction {

    public abstract List<ProtocolMessage> getSendMessages();

    public abstract List<Record> getSendRecords();

    public abstract List<DtlsHandshakeMessageFragment> getSendFragments();

    public default List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        return new ArrayList<>();
    }

    public default List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        return new ArrayList<>();
    }
}
