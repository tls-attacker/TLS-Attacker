/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement
public class TightReceiveAction extends ReceiveAction {

    public TightReceiveAction() {}

    public TightReceiveAction(List<ProtocolMessage> expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(ProtocolMessage... expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        super(myActionOptions, messages);
    }

    public TightReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        super(actionOptions, messages);
    }

    public TightReceiveAction(ActionOption actionOption, List<ProtocolMessage> messages) {
        super(actionOption, messages);
    }

    public TightReceiveAction(ActionOption actionOption, ProtocolMessage... messages) {
        super(actionOption, messages);
    }

    public TightReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public TightReceiveAction(String connectionAliasAlias, List<ProtocolMessage> messages) {
        super(connectionAliasAlias, messages);
    }

    public TightReceiveAction(String connectionAliasAlias, ProtocolMessage... messages) {
        super(connectionAliasAlias, messages);
    }

    @Override
    protected void distinctReceive(TlsContext tlsContext) {
        tightReceive(tlsContext, getExpectedMessages());
    }
}
