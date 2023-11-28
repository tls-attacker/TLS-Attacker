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
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveQuicAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> expectedQuicFrames = null;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> expectedQuicPackets = null;

    public ReceiveQuicAction() {
        super();
    }

    public ReceiveQuicAction(QuicFrame... expectedQuicFrames) {
        super();
        this.expectedQuicFrames = new ArrayList<>(Arrays.asList(expectedQuicFrames));
    }

    public ReceiveQuicAction(QuicPacket... expectedQuicPackets) {
        super();
        this.expectedQuicPackets = new ArrayList<>(Arrays.asList(expectedQuicPackets));
    }

    public ReceiveQuicAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        this(expectedQuicFrames);
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveQuicAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        this(expectedQuicPackets);
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveQuicAction(
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        this.expectedQuicFrames = new ArrayList<>(expectedQuicFrames);
        this.expectedQuicPackets = new ArrayList<>(expectedQuicPackets);
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveQuicAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        this.expectedQuicFrames = new ArrayList<>(expectedQuicFrames);
        this.expectedQuicPackets = new ArrayList<>(expectedQuicPackets);
        setActionOptions(actionOptions);
    }

    @Override
    protected List<LayerConfiguration> createLayerConfiguration(TlsContext tlsContext) {
        return createReceivLayerConfiguration(
                tlsContext, null, null, null, expectedQuicFrames, expectedQuicPackets, null);
    }
}
