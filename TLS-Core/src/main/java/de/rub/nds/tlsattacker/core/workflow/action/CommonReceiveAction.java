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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.List;

public abstract class CommonReceiveAction extends MessageAction {

    public CommonReceiveAction() {
        super();
    }

    public CommonReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving... (" + this.getClass().getSimpleName() + ")");
        List<LayerConfiguration> layerConfigurations = createLayerConfiguration(tlsContext);
        getReceiveResult(tlsContext.getLayerStack(), layerConfigurations);
        setExecuted(true);

        String expected = getReadableString(layerConfigurations);
        LOGGER.debug("Receive Expected: {}", expected);
        String received = getReadableString(getLayerStackProcessingResult());
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: {}", received);
        } else {
            LOGGER.info("Received Messages ({}): {}", getConnectionAlias(), received);
        }
    }

    protected abstract List<LayerConfiguration> createLayerConfiguration(TlsContext tlsContext);
}
