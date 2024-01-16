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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@XmlRootElement
public class ReceiveQuicTillAction extends CommonReceiveAction {

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> expectedQuicFrames = null;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> expectedQuicPackets = null;

    public ReceiveQuicTillAction() {
        super();
    }

    public ReceiveQuicTillAction(QuicFrame... expectedQuicFrames) {
        super();
        this.expectedQuicFrames = new ArrayList<>(Arrays.asList(expectedQuicFrames));
    }

    public ReceiveQuicTillAction(QuicPacket... expectedQuicPackets) {
        super();
        this.expectedQuicPackets = new ArrayList<>(Arrays.asList(expectedQuicPackets));
    }

    public ReceiveQuicTillAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        super(Set.of(actionOption));
        this.expectedQuicFrames = new ArrayList<>(Arrays.asList(expectedQuicFrames));
    }

    public ReceiveQuicTillAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        super(Set.of(actionOption));
        this.expectedQuicPackets = new ArrayList<>(Arrays.asList(expectedQuicPackets));
    }

    public ReceiveQuicTillAction(
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(Set.of(actionOption));
        this.expectedQuicFrames = expectedQuicFrames;
        this.expectedQuicPackets = expectedQuicPackets;
    }

    public ReceiveQuicTillAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOptions);
        this.expectedQuicFrames = expectedQuicFrames;
        this.expectedQuicPackets = expectedQuicPackets;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        return ActionHelperUtil.createReceiveTillConfiguration(
                tlsContext, expectedQuicFrames, expectedQuicPackets);
    }
}
