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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "GenericReceive")
public class GenericReceiveAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

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
        return ActionHelperUtil.createReceiveLayerConfiguration(
                tlsContext, getActionOptions(), null, null, null, null, null, null);
    }
}
