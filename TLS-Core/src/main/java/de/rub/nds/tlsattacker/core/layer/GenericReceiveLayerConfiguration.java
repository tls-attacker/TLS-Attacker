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
import java.util.LinkedList;
import java.util.List;

/** A LayerConfiguration that keeps receiving until reaching the timeout */
public class GenericReceiveLayerConfiguration extends ReceiveLayerConfiguration<DataContainer> {

    public GenericReceiveLayerConfiguration(LayerType layerType) {
        super(layerType, new LinkedList<>());
    }

    @Override
    public boolean isProcessTrailingContainers() {
        return true;
    }

    @Override
    public boolean executedAsPlanned(List<DataContainer> list) {
        return true;
    }

    @Override
    public boolean failedEarly(List<DataContainer> list) {
        return false;
    }
}
