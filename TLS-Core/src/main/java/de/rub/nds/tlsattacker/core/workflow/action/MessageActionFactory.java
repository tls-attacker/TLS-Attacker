/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MessageActionFactory {

    /**
     * Java cannot automatically parse ProtocolMessage lists to Message lists when calling
     * createAction, so we have these two wrapper methods.
     */
    public static MessageAction createTLSAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEndType,
            ProtocolMessage... protocolMessages) {
        return createTLSAction(
                tlsConfig,
                connection,
                sendingConnectionEndType,
                new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    public static MessageAction createHttpAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEndType,
            HttpMessage... httpMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEndType) {
            action = new SendAction(httpMessages);
        } else {
            action = new ReceiveAction(httpMessages);
            action.setActionOptions(getFactoryReceiveActionOptions(tlsConfig));
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static MessageAction createTLSAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage> protocolMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages);
        } else {
            action = new ReceiveAction(getFactoryReceiveActionOptions(tlsConfig), protocolMessages);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static MessageAction createQuicAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            QuicFrame... quicFrames) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(quicFrames);
        } else {
            action = new ReceiveAction(quicFrames);
            action.setActionOptions(getFactoryReceiveActionOptions(tlsConfig));
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static MessageAction createQuicAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            QuicPacket... quicPackets) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(quicPackets);
        } else {
            action = new ReceiveAction(quicPackets);
            action.setActionOptions(getFactoryReceiveActionOptions(tlsConfig));
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static MessageAction createQuicAction(
            Config tlsConfig,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(null, quicFrames, quicPackets);
        } else {
            action =
                    new ReceiveAction(
                            getFactoryReceiveActionOptions(tlsConfig), quicFrames, quicPackets);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    private static Set<ActionOption> getFactoryReceiveActionOptions(Config tlsConfig) {
        Set<ActionOption> globalOptions = new HashSet<>();
        if (tlsConfig.getMessageFactoryActionOptions().contains(ActionOption.CHECK_ONLY_EXPECTED)) {
            globalOptions.add(ActionOption.CHECK_ONLY_EXPECTED);
        }
        if (tlsConfig
                .getMessageFactoryActionOptions()
                .contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS)) {
            globalOptions.add(ActionOption.IGNORE_UNEXPECTED_WARNINGS);
        }
        if (tlsConfig.getMessageFactoryActionOptions().contains(ActionOption.IGNORE_ACK_MESSAGES)) {
            globalOptions.add(ActionOption.IGNORE_ACK_MESSAGES);
        }
        if (tlsConfig
                .getMessageFactoryActionOptions()
                .contains(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS)) {
            globalOptions.add(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
        }

        return globalOptions;
    }

    private MessageActionFactory() {}
}
