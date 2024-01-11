/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.TightReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement(name = "TightReceive")
public class TightReceiveAction extends CommonReceiveAction {

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> expectedMessages;

    public TightReceiveAction() {}

    public TightReceiveAction(List<ProtocolMessage> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public TightReceiveAction(ProtocolMessage... expectedMessages) {
        super();
        this.expectedMessages = Arrays.asList(expectedMessages);
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new TightReceiveLayerConfiguration(ImplementedLayers.MESSAGE, expectedMessages));
        return ActionHelperUtil.sortLayerConfigurations(
                tlsContext.getLayerStack(), false, configurationList);
    }
}
