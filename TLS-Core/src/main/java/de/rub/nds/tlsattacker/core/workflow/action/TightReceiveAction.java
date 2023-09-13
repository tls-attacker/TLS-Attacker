/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement
public class TightReceiveAction extends CommonReceiveAction {

    public TightReceiveAction() {}

    public TightReceiveAction(List<ProtocolMessage<?>> expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(ProtocolMessage<?>... expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public TightReceiveAction(String connectionAliasAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAliasAlias, messages);
    }

    public TightReceiveAction(String connectionAliasAlias, ProtocolMessage<?>... messages) {
        super(connectionAliasAlias, messages);
    }

    @Override
    protected List<LayerConfiguration<?>> createConfigurationList() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createConfigurationList'");
    }
}
