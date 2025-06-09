/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;

public class IgnoreLayerConfiguration<Container extends DataContainer<Context>>
        extends LayerConfiguration<Container> {

    public IgnoreLayerConfiguration(LayerType layerType) {
        super(layerType, new LinkedList<>());
    }

    @Override
    public String toCompactString() {
        return "(ignored)";
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return true;
    }

    @Override
    public boolean shouldContinueProcessing(
            List<Container> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        return false;
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return level.isMoreSpecificThan(Level.INFO); // DEBUG, TRACE etc should log it.
    }
}
