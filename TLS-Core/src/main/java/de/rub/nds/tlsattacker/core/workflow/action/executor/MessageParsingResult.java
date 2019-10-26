/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import java.util.List;

public class MessageParsingResult {
    private List<ProtocolMessage> messages;
    private List<DtlsHandshakeMessageFragment> messageFragments;
    private List<DtlsMessageInformation> messageInfos;

    public MessageParsingResult(List<ProtocolMessage> messages, List<DtlsHandshakeMessageFragment> messageFragments,
            List<DtlsMessageInformation> messageInfos) {
        super();
        this.messages = messages;
        this.messageFragments = messageFragments;
        this.messageInfos = messageInfos;
    }

    public List<ProtocolMessage> getMessages() {
        return messages;
    }

    public List<DtlsHandshakeMessageFragment> getMessageFragments() {
        return messageFragments;
    }

    public List<DtlsMessageInformation> getMessageInfos() {
        return messageInfos;
    }

}
