/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

import de.rub.nds.tlsattacker.core.layer.data.DataContainer;

/**
 * Send configuration that sends a list of containers to the recipient.
 *
 * @param <Container>
 */
public class SpecificSendLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    public SpecificSendLayerConfiguration(List<Container> containerList) {
        super(containerList);
    }

    public SpecificSendLayerConfiguration(Container... containers) {
        super(containers);
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        if (list == null) {
            return false;
        }
        if (getContainerList() == null) {
            return true;
        }
        return list.size() == getContainerList().size();
    }

    @Override
    public boolean failedEarly(List<Container> list) {
        return false;
    }

}
