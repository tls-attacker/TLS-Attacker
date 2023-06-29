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
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.ArrayList;
import java.util.List;

public interface ReceivingAction {

    public abstract List<ProtocolMessage> getReceivedMessages();

    public abstract List<Record> getReceivedRecords();

    public abstract List<DtlsHandshakeMessageFragment> getReceivedFragments();

    public abstract List<HttpMessage> getReceivedHttpMessages();

    public default List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        return new ArrayList<>();
    }

    public default List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        return new ArrayList<>();
    }
}
