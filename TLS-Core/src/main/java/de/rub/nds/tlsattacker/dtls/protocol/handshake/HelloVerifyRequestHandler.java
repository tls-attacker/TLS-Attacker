/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.dtls.protocol.handshake;

import java.util.Arrays;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @param <HandshakeMessage>
 */
public class HelloVerifyRequestHandler<Message extends HelloVerifyRequestMessage> extends
        HandshakeMessageHandler<Message> {

    @SuppressWarnings("unchecked")
    public HelloVerifyRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = (Class<? extends Message>) HelloVerifyRequestMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
        byte[] content;
        protocolMessage.setProtocolVersion(tlsContext.getConfig().getProtocolVersion().getValue());

        // TODO: Calculate cookie via HMAC
        byte[] cookie = new byte[3];
        cookie[0] = (byte) 11;
        cookie[1] = (byte) 22;
        cookie[2] = (byte) 33;

        tlsContext.setDtlsHandshakeCookie(cookie);
        protocolMessage.setCookie(cookie);
        protocolMessage.setCookieLength((byte) cookie.length);

        content = ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(),
                new byte[] { protocolMessage.getCookieLength().getValue() }, protocolMessage.getCookie().getValue());

        protocolMessage.setLength(content.length);

        protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
                new byte[] { HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue() },
                ArrayConverter.intToBytes(protocolMessage.getLength().getValue(), 3), content));

        return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        if (message[pointer] != HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue()) {
            throw new InvalidMessageTypeException("This is not a client verify message");
        }
        protocolMessage.setType(message[pointer]);

        int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
        int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
        int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setLength(length);

        currentPointer = nextPointer;
        nextPointer = currentPointer + RecordByteLength.PROTOCOL_VERSION;
        ProtocolVersion serverProtocolVersion = ProtocolVersion.getProtocolVersion(Arrays.copyOfRange(message,
                currentPointer, nextPointer));
        protocolMessage.setProtocolVersion(serverProtocolVersion.getValue());

        currentPointer = nextPointer;
        nextPointer += HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH;
        int cookieLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));

        byte[] cookie;
        currentPointer = nextPointer;
        nextPointer += cookieLength;
        cookie = Arrays.copyOfRange(message, currentPointer, nextPointer);
        protocolMessage.setCookie(cookie);
        protocolMessage.setCookieLength((byte) cookie.length);
        tlsContext.setDtlsHandshakeCookie(cookie);

        return nextPointer;
    }
}
