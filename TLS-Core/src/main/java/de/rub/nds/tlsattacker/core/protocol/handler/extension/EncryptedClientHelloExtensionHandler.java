/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeReceiverContext;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloExtensionHandler
        extends ExtensionHandler<EncryptedClientHelloExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedClientHelloExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(EncryptedClientHelloExtensionMessage message) {

        // adjust tls context if we received this message from the client

        if (tlsContext.getConnection().getLocalConnectionEndType() == ConnectionEndType.SERVER
                && message.getEchClientHelloType() == EchClientHelloType.OUTER) {

            EchConfig echConfig = tlsContext.getChooser().getEchConfig();

            if (message.getConfigId().getValue() != echConfig.getConfigId()) {
                LOGGER.warn("ECHConfig id's do not match");
            }

            LOGGER.debug("Received ECH Config ID: " + message.getConfigId().getValue());
            LOGGER.debug("Own ECH Config ID: " + echConfig.getConfigId());

            HpkeUtil hpkeUtil = new HpkeUtil(echConfig);
            KeyShareEntry keyShareEntry = tlsContext.getChooser().getEchServerKeyShareEntry();

            // log own private and public key
            LOGGER.debug(
                    "ServerPrivateKey: "
                            + ArrayConverter.bytesToHexString(
                                    keyShareEntry.getPrivateKey().toByteArray()));
            LOGGER.debug(
                    "ServerPublicKey: "
                            + ArrayConverter.bytesToHexString(
                                    keyShareEntry.getPublicKey().getValue()));

            // RFC 9180, Section 7.1
            byte[] info =
                    ArrayConverter.concatenate(
                            "tls ech".getBytes(), new byte[] {0x00}, echConfig.getEchConfigBytes());
            LOGGER.debug("Info: " + ArrayConverter.bytesToHexString(info));

            byte[] payload = message.getPayload().getValue();
            LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(payload));

            // extract aad from clientHelloOuter by replacing payload with zero bytes

            // The last client hello is the aad for the encryption but without its header
            // information
            byte[] aad =
                    Arrays.copyOfRange(
                            tlsContext.getLastClientHello(),
                            HandshakeByteLength.TYPE_LENGTH
                                    + HandshakeByteLength.HANDSHAKE_MESSAGE_LENGTH_FIELD_LENGTH,
                            tlsContext.getLastClientHello().length);
            int startIndex = HpkeUtil.indexOf(aad, payload);
            System.arraycopy(new byte[payload.length], 0, aad, startIndex, payload.length);
            LOGGER.debug("AAD: " + ArrayConverter.bytesToHexString(aad));
            byte[] encodedClientHelloInner;
            try {
                HpkeReceiverContext receiverContext =
                        hpkeUtil.setupBaseReceiver(
                                message.getEnc().getValue(), info, keyShareEntry);
                encodedClientHelloInner = receiverContext.open(aad, payload);
                LOGGER.debug(
                        "Encoded ClientHello Inner"
                                + ArrayConverter.bytesToHexString(encodedClientHelloInner));
            } catch (CryptoException e) {
                LOGGER.warn("Could not decrypt the sent ECH (tag mismatch?): ", e);
                return;
            }

            LOGGER.debug(
                    "Encoded client hello inner: "
                            + ArrayConverter.bytesToHexString(encodedClientHelloInner));
            // parse clienthelloinner if possible
            // first add version and length bytes to encoded clienthelloinner
            byte[] type = new byte[] {HandshakeMessageType.CLIENT_HELLO.getValue()};
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage();
            try {
                ClientHelloParser clientHelloParser =
                        new ClientHelloParser(
                                new ByteArrayInputStream(encodedClientHelloInner), tlsContext);
                clientHelloParser.parse(clientHelloMessage);
                // for some reason we have to determine the actual length of the client hello AFTER
                // we parsed it
                // therefore, we have to overwrite the length here
                int clientHelloMessageLength = clientHelloParser.getAlreadyParsed().length;
                byte[] clientHelloLength =
                        ArrayConverter.intToBytes(
                                clientHelloMessageLength,
                                HandshakeByteLength.HANDSHAKE_MESSAGE_LENGTH_FIELD_LENGTH);
                clientHelloMessage.setLength(clientHelloMessageLength);
                clientHelloMessage.setCompleteResultingMessage(
                        ArrayConverter.concatenate(
                                type, clientHelloLength, clientHelloParser.getAlreadyParsed()));
            } catch (ParserException e) {
                LOGGER.warn("Could not parse decrypted ClientHello", e);
                return;
            }

            // if we made it to here the client sent a correct ECH extension and (finally) adjust
            // context
            tlsContext.setSupportsECH(true);
            ClientHelloHandler clientHelloHandler = new ClientHelloHandler(tlsContext);
            clientHelloHandler.adjustContext(clientHelloMessage);
            tlsContext.getDigest().reset();
            clientHelloHandler.updateDigest(clientHelloMessage, true);
            LOGGER.info("Client supports ECH");
        }
    }
}
