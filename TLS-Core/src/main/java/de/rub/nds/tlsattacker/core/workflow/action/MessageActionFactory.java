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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.*;

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

        return globalOptions;
    }

    private MessageActionFactory() {}
}
