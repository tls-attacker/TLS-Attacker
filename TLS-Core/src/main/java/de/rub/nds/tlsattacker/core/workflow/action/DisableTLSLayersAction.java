/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DisableTLSLayersAction extends ConnectionBoundAction {
    DisableLayerAction disableLayersAction =
            new DisableLayerAction(ImplementedLayers.MESSAGE, ImplementedLayers.RECORD);

    @Override
    public void execute(State state) throws ActionExecutionException {
        disableLayersAction.execute(state);
        setExecuted(true);
    }

    @Override
    public void reset() {
        disableLayersAction.reset();
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return disableLayersAction.executedAsPlanned();
    }
}
