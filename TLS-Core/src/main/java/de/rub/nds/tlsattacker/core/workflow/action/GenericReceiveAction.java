/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement(name = "GenericReceive")
public class GenericReceiveAction extends CommonReceiveAction {

    public GenericReceiveAction() {
        super();
    }

    public GenericReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(new GenericReceiveLayerConfiguration(ImplementedLayers.MESSAGE));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), false, getActionOptions(), configurationList);
    }
}
