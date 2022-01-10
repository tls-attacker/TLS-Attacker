/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 */
public class ResponseExtractor {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param  state
     * @param  action
     * @return
     */
    public static ResponseFingerprint getFingerprint(State state, ReceivingAction action) {
        List<TlsMessage> messageList = action.getReceivedMessages();
        List<Record> recordList = action.getReceivedRecords();
        SocketState socketState = extractSocketState(state);
        return new ResponseFingerprint(messageList, recordList, socketState);
    }

    /**
     *
     * @param  state
     * @return
     */
    public static ResponseFingerprint getFingerprint(State state) {
        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        return getFingerprint(state, action);
    }

    private static SocketState extractSocketState(State state) {
        if (state.getTlsContext().getTransportHandler() instanceof ClientTcpTransportHandler) {
            SocketState socketState =
                (((ClientTcpTransportHandler) (state.getTlsContext().getTransportHandler())).getSocketState());
            return socketState;
        } else {
            return null;
        }
    }

    private static List<Class<Record>> extractRecordClasses(ReceivingAction action) {
        List<Class<Record>> classList = new LinkedList<>();
        if (action.getReceivedRecords() != null) {
            for (Record record : action.getReceivedRecords()) {
                classList.add((Class<Record>) record.getClass());
            }
        }
        return classList;
    }

    private static List<Class<TlsMessage>> extractMessageClasses(ReceivingAction action) {
        List<Class<TlsMessage>> classList = new LinkedList<>();
        if (action.getReceivedMessages() != null) {
            for (TlsMessage message : action.getReceivedMessages()) {
                classList.add((Class<TlsMessage>) message.getClass());
            }
        }
        return classList;
    }

    private static boolean didReceiveEncryptedAlert(ReceivingAction action) {
        if (action.getReceivedRecords() != null) {
            for (Record abstractRecord : action.getReceivedRecords()) {
                if (abstractRecord instanceof Record) {
                    Record record = (Record) abstractRecord;
                    if (record.getContentMessageType() == ProtocolMessageType.ALERT) {
                        if (record.getLength().getValue() > 6) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private ResponseExtractor() {
    }
}
