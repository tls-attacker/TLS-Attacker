/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @param <ProtocolMessage>
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
        ProtocolMessageHandler<ProtocolMessage> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    // @Override
    // protected byte[] beforeParseMessageAction(byte[] message, int pointer) {
    // if (tlsContext.getConfig().getHighestProtocolVersion() ==
    // ProtocolVersion.DTLS12) {
    // return prepareDtlsHandshakeMessageParse(message, pointer);
    // }
    // return message;
    // }

    // /**
    // * Implementation hook used after the prepareMessageAction: the content of
    // * the parsed protocol message is parsed and the digest value is updated
    // *
    // * @param messageBytes
    // * @return
    // */
    // @Override
    // protected byte[] afterPrepareMessageAction(byte[] messageBytes) {
    // if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.DTLS12) {
    // protocolMessage.setCompleteResultingMessage(finishDtlsHandshakeMessagePrepare(messageBytes));
    // }
    // byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
    // if (protocolMessage.getIncludeInDigest()) {
    // tlsContext.getDigest().update(pm);
    // }
    // return pm;
    // }

    // /**
    // * Implementation hook used after the parseMessageAction: the content of
    // the
    // * parsed protocol message is parsed and the digest value is updated
    // *
    // * @param ret
    // * @return
    // */
    // @Override
    // protected int afterParseMessageAction(int ret) {
    // if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.DTLS12) {
    // protocolMessage.setCompleteResultingMessage(dtlsAllMessageBytes);
    // ret += 8;
    // }
    // byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
    // if (protocolMessage.getIncludeInDigest()) {
    // tlsContext.getDigest().update(pm);
    // }
    // return ret;
    // }

    // private byte[] prepareDtlsHandshakeMessageParse(byte[] message, int
    // pointer) {
    // dtlsAllMessageBytes = message;
    // byte[] parsePmBytes;
    // protocolMessage.setMessageSeq((message[pointer + 4] << 8) +
    // (message[pointer + 5] & 0xFF));
    // protocolMessage.setFragmentOffset((message[pointer + 6] << 16) +
    // (message[pointer + 7] << 8)
    // + (message[pointer + 8] & 0xFF));
    // protocolMessage.setFragmentLength((message[pointer + 9] << 16) +
    // (message[pointer + 10] << 8)
    // + (message[pointer + 11] & 0xFF));
    //
    // parsePmBytes = new byte[message.length - 8];
    // System.arraycopy(message, 0, parsePmBytes, 0, pointer);
    // System.arraycopy(message, pointer, parsePmBytes, pointer, 4);
    // System.arraycopy(message, pointer + 12, parsePmBytes, pointer + 4,
    // message.length - pointer - 12);
    //
    // return parsePmBytes;
    // }

    // private byte[] finishDtlsHandshakeMessagePrepare(byte[] messageBytes) {
    // protocolMessage.setFragmentLength(messageBytes.length - 4);
    // byte[] preparePmBytes = new byte[messageBytes.length + 8];
    //
    // System.arraycopy(messageBytes, 0, preparePmBytes, 0, 4);
    //
    // if (protocolMessage.getMessageSeq().getValue() != null) {
    // System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getMessageSeq().getValue(),
    // 2), 0,
    // preparePmBytes, 4, 2);
    // } else if (tlsContext.getConfig().isFuzzingMode()) {
    // System.arraycopy(ArrayConverter.intToBytes(0, 2), 0, preparePmBytes, 4,
    // 2);
    // } else {
    // throw new
    // WorkflowExecutionException("ProtocolMessage messageSequence is null!");
    // }
    // if (protocolMessage.getFragmentOffset().getValue() != null) {
    // System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getFragmentOffset().getValue(),
    // 3), 0,
    // preparePmBytes, 6, 3);
    // } else if (tlsContext.getConfig().isFuzzingMode()) {
    // System.arraycopy(ArrayConverter.intToBytes(0, 3), 0, preparePmBytes, 6,
    // 3);
    // } else {
    // throw new
    // WorkflowExecutionException("ProtocolMessage FragmentOffset is null!");
    // }
    // if (protocolMessage.getFragmentLength().getValue() != null) {
    // System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getFragmentLength().getValue(),
    // 3), 0,
    // preparePmBytes, 9, 3);
    // } else if (tlsContext.getConfig().isFuzzingMode()) {
    // System.arraycopy(ArrayConverter.intToBytes(0, 3), 0, preparePmBytes, 9,
    // 3);
    // } else {
    // throw new
    // WorkflowExecutionException("ProtocolMessage FragmentOffset is null!");
    // }
    // System.arraycopy(messageBytes, 4, preparePmBytes, 12, messageBytes.length
    // - 4);
    //
    // return preparePmBytes;
    // }

}
