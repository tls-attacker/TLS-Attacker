/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;

/**
 * Send configuration that sends a list of containers to the recipient.
 *
 * @param <Container>
 */
public class SpecificSendLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    public SpecificSendLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    public SpecificSendLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
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
