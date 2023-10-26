/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveQuicTillAction extends ReceiveQuicAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "maxNumberOfQuicPacketsToReceive")
    protected Integer maxNumberOfQuicPacketsToReceive = 5;

    public ReceiveQuicTillAction() {
        super();
    }

    public ReceiveQuicTillAction(QuicFrame... expectedQuicFrames) {
        super(expectedQuicFrames);
    }

    public ReceiveQuicTillAction(QuicPacket... expectedQuicPackets) {
        super(expectedQuicPackets);
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive, QuicFrame... expectedQuicFrames) {
        super(expectedQuicFrames);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive, QuicPacket... expectedQuicPackets) {
        super(expectedQuicPackets);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    public ReceiveQuicTillAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        super(actionOption, expectedQuicFrames);
    }

    public ReceiveQuicTillAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        super(actionOption, expectedQuicPackets);
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive,
            ActionOption actionOption,
            QuicFrame... expectedQuicFrames) {
        super(actionOption, expectedQuicFrames);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive,
            ActionOption actionOption,
            QuicPacket... expectedQuicPackets) {
        super(actionOption, expectedQuicPackets);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    public ReceiveQuicTillAction(
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOption, expectedQuicFrames, expectedQuicPackets);
    }

    public ReceiveQuicTillAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOptions, expectedQuicFrames, expectedQuicPackets);
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive,
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOption, expectedQuicFrames, expectedQuicPackets);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    public ReceiveQuicTillAction(
            int maxNumberOfQuicPacketsToReceive,
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOptions, expectedQuicFrames, expectedQuicPackets);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
    }

    @Override
    protected void distinctReceive(TlsContext tlsContext) {
        receiveTillQuic(
                tlsContext,
                expectedQuicFrames,
                expectedQuicPackets,
                maxNumberOfQuicPacketsToReceive);
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    LOGGER.error(
                            "ReceiveAction failed: Layer {}, did not execute as planned",
                            result.getLayerType());
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
