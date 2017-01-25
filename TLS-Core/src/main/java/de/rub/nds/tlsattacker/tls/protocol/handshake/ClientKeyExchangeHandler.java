/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import java.util.Arrays;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <HandshakeMessage>
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    protected KeyExchangeAlgorithm keyExchangeAlgorithm;

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public byte[] prepareMessageAction() {
        protocolMessage.setType(HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue());
        CipherSuite selectedCipherSuite = tlsContext.getSelectedCipherSuite();
        KeyExchangeAlgorithm keyExchange = AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite);
        if (keyExchange != keyExchangeAlgorithm) {
            throw new UnsupportedOperationException("The selected key exchange algorithm (" + keyExchange
                    + ") is not supported yet");
        }

        byte[] result = this.prepareKeyExchangeMessage();
        protocolMessage.setLength(result.length);
        long header = (protocolMessage.getType().getValue() << 24) + protocolMessage.getLength().getValue();
        protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
                ArrayConverter.longToUint32Bytes(header), result));

        return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        if (message[pointer] != HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue()) {
            throw new InvalidMessageTypeException("This is not a Client key exchange message");
        }
        protocolMessage.setType(message[pointer]);

        int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
        int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
        int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setLength(length);
        currentPointer = nextPointer;

        int resultPointer = this.parseKeyExchangeMessage(message, currentPointer);

        currentPointer = resultPointer;

        protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, currentPointer));

        return currentPointer;
    }

    abstract byte[] prepareKeyExchangeMessage();

    abstract int parseKeyExchangeMessage(byte[] message, int pointer);
}
