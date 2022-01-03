/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MessageActionFactory {

    public static MessageAction createAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEndType, ProtocolMessage... protocolMessages) {
        return createAction(tlsConfig, connection, sendingConnectionEndType,
            new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    public static MessageAction createAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, List<ProtocolMessage> protocolMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages);
        } else {
            action = new ReceiveAction(getFactoryReceiveActionOptions(tlsConfig), protocolMessages);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static AsciiAction createAsciiAction(AliasedConnection connection, ConnectionEndType sendingConnectionEnd,
        String message, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAsciiAction(message, encoding);
        } else {
            action = new GenericReceiveAsciiAction(encoding);
        }
        return action;
    }

    private MessageActionFactory() {
    }

    private static Set<ActionOption> getFactoryReceiveActionOptions(Config tlsConfig) {
        Set<ActionOption> globalOptions = new HashSet<>();
        if (tlsConfig.getMessageFactoryActionOptions().contains(ActionOption.CHECK_ONLY_EXPECTED)) {
            globalOptions.add(ActionOption.CHECK_ONLY_EXPECTED);
        }
        if (tlsConfig.getMessageFactoryActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS)) {
            globalOptions.add(ActionOption.IGNORE_UNEXPECTED_WARNINGS);
        }

        return globalOptions;
    }
}
