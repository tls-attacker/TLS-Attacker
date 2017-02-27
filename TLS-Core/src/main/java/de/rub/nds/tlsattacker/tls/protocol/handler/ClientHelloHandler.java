/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.Time;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public class ClientHelloHandler<Message extends ClientHelloMessage> extends HandshakeMessageHandler<Message> {

    public ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    //
    // @Override
    // public byte[] prepareMessageAction() {
    // protocolMessage.setProtocolVersion(tlsContext.getConfig().getHighestProtocolVersion().getValue());
    // protocolMessage.setSessionId(tlsContext.getConfig().getSessionId());
    // int length = protocolMessage.getSessionId().getValue().length;
    // protocolMessage.setSessionIdLength(length);
    // final long unixTime = Time.getUnixTime();
    // protocolMessage.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));
    // byte[] random = new byte[HandshakeByteLength.RANDOM];
    // RandomHelper.getRandom().nextBytes(random);
    // protocolMessage.setRandom(random);
    // tlsContext.setClientRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(),
    // protocolMessage
    // .getRandom().getValue()));
    // byte[] cookieArray = new byte[0];
    // // Ugly but more secure
    // if (protocolMessage instanceof ClientHelloDtlsMessage) {
    // ClientHelloDtlsMessage dtlsClientHello =
    // (de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage)
    // protocolMessage;
    // dtlsClientHello.setCookie(tlsContext.getDtlsHandshakeCookie());
    // dtlsClientHello.setCookieLength((byte)
    // tlsContext.getDtlsHandshakeCookie().length);
    // cookieArray = ArrayConverter.concatenate(new byte[] {
    // dtlsClientHello.getCookieLength().getValue() },
    // dtlsClientHello.getCookie().getValue());
    // }
    //
    // byte[] cipherSuites = new byte[0];
    // for (CipherSuite cs : tlsContext.getConfig().getSupportedCiphersuites())
    // {
    // cipherSuites = ArrayConverter.concatenate(cipherSuites,
    // cs.getByteValue());
    // }
    // protocolMessage.setCipherSuites(cipherSuites);
    // int cipherSuiteLength = 0;
    // cipherSuiteLength = protocolMessage.getCipherSuites().getValue().length;
    // protocolMessage.setCipherSuiteLength(cipherSuiteLength);
    //
    // byte[] compressionMethods = new byte[0];
    // for (CompressionMethod cm :
    // tlsContext.getConfig().getSupportedCompressionMethods()) {
    // compressionMethods = ArrayConverter.concatenate(compressionMethods,
    // cm.getArrayValue());
    // }
    // protocolMessage.setCompressions(compressionMethods);
    //
    // int compressionMethodLength =
    // protocolMessage.getCompressions().getValue().length;
    // protocolMessage.setCompressionLength(compressionMethodLength);
    //
    // byte[] result =
    // ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(),
    // protocolMessage
    // .getUnixTime().getValue(), protocolMessage.getRandom().getValue(),
    // ArrayConverter.intToBytes(
    // protocolMessage.getSessionIdLength().getValue(), 1),
    // protocolMessage.getSessionId().getValue(),
    // cookieArray,
    // ArrayConverter.intToBytes(protocolMessage.getCipherSuiteLength().getValue(),
    // HandshakeByteLength.CIPHER_SUITE),
    // protocolMessage.getCipherSuites().getValue(),
    // ArrayConverter.intToBytes(protocolMessage.getCompressionLength().getValue(),
    // HandshakeByteLength.COMPRESSION),
    // protocolMessage.getCompressions().getValue());
    //
    // byte[] extensionBytes = null;
    //
    // if (tlsContext.getConfig().isMitm()) {
    // // extensionBytes = protocolMessage.getExtensionBytes();
    // result = ArrayConverter.concatenate(result, extensionBytes);
    // } else {
    // for (ExtensionMessage extension : protocolMessage.getExtensions()) {
    // // ExtensionHandler handler = extension.getExtensionHandler();
    // // handler.setExtensionMessage(extension);
    // // handler.prepareExtension(tlsContext);
    // // extensionBytes = ArrayConverter.concatenate(extensionBytes,
    // // extension.getExtensionBytes().getValue());
    // }
    //
    // if (extensionBytes != null && extensionBytes.length != 0) {
    // byte[] extensionLength = ArrayConverter.intToBytes(extensionBytes.length,
    // ExtensionByteLength.EXTENSIONS_LENGTH);
    // protocolMessage.setExtensionsLength(extensionBytes.length);
    // result = ArrayConverter.concatenate(result, extensionLength,
    // extensionBytes);
    // } else {
    // protocolMessage.setExtensionsLength(0);
    // }
    // }
    //
    // protocolMessage.setLength(result.length);
    //
    // long header = (HandshakeMessageType.CLIENT_HELLO.getValue() << 24) +
    // protocolMessage.getLength().getValue();
    //
    // protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
    // ArrayConverter.longToUint32Bytes(header), result));
    //
    // return protocolMessage.getCompleteResultingMessage().getValue();
    // }
    //
    // @Override
    // public int parseMessageAction(byte[] message, int pointer) {
    // if (message[pointer] != HandshakeMessageType.CLIENT_HELLO.getValue()) {
    // throw new
    // InvalidMessageTypeException("This is not a client hello message");
    // }
    // protocolMessage.setType(message[pointer]);
    //
    // int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
    // int nextPointer = currentPointer +
    // HandshakeByteLength.MESSAGE_LENGTH_FIELD;
    // int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message,
    // currentPointer, nextPointer));
    // protocolMessage.setLength(length);
    //
    // currentPointer = nextPointer;
    // nextPointer = currentPointer + RecordByteLength.PROTOCOL_VERSION;
    // ProtocolVersion highestClientVersion =
    // ProtocolVersion.getProtocolVersion(Arrays.copyOfRange(message,
    // currentPointer, nextPointer));
    // protocolMessage.setProtocolVersion(highestClientVersion.getValue());
    // tlsContext.setHighestClientProtocolVersion(highestClientVersion);
    // currentPointer = nextPointer;
    // nextPointer = currentPointer + HandshakeByteLength.UNIX_TIME;
    // protocolMessage.setUnixTime(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    //
    // currentPointer = nextPointer;
    // nextPointer = currentPointer + HandshakeByteLength.RANDOM;
    // protocolMessage.setRandom(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    //
    // tlsContext.setClientRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(),
    // protocolMessage
    // .getRandom().getValue()));
    //
    // currentPointer = nextPointer;
    // nextPointer += HandshakeByteLength.SESSION_ID_LENGTH;
    // int sessionIdLength =
    // ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    // protocolMessage.setSessionIdLength(sessionIdLength);
    //
    // currentPointer = nextPointer;
    // nextPointer += sessionIdLength;
    // protocolMessage.setSessionId(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    //
    // // handle unknown SessionID during Session resumption
    // if (tlsContext.getConfig().isSessionResumption()
    // && !(Arrays.equals(tlsContext.getSessionID(),
    // protocolMessage.getSessionId().getValue()))) {
    // throw new
    // WorkflowExecutionException("Session ID is unknown to the Server");
    // }
    // // TODO !!!
    // if (tlsContext.getConfig().getHighestProtocolVersion() ==
    // ProtocolVersion.DTLS12
    // || tlsContext.getConfig().getHighestProtocolVersion() ==
    // ProtocolVersion.DTLS10) {
    // de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage
    // dtlsClientHello =
    // (de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage)
    // protocolMessage;
    // currentPointer = nextPointer;
    // nextPointer += HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH;
    // byte cookieLength = message[currentPointer];
    // dtlsClientHello.setCookieLength(cookieLength);
    //
    // currentPointer = nextPointer;
    // nextPointer += cookieLength;
    // dtlsClientHello.setCookie(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    // }
    //
    // currentPointer = nextPointer;
    // nextPointer += HandshakeByteLength.CIPHER_SUITE;
    // int cipherSuitesLength =
    // ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    // protocolMessage.setCipherSuiteLength(cipherSuitesLength);
    //
    // currentPointer = nextPointer;
    // nextPointer += cipherSuitesLength;
    // protocolMessage.setCipherSuites(Arrays.copyOfRange(message,
    // currentPointer, nextPointer));
    //
    // tlsContext.setClientSupportedCiphersuites(CipherSuite.getCiphersuites(protocolMessage.getCipherSuites()
    // .getValue()));
    // currentPointer = nextPointer;
    // nextPointer += HandshakeByteLength.COMPRESSION;
    // int compressionsLength =
    // ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
    // nextPointer));
    // protocolMessage.setCompressionLength(compressionsLength);
    //
    // currentPointer = nextPointer;
    // nextPointer += compressionsLength;
    // protocolMessage.setCompressions(Arrays.copyOfRange(message,
    // currentPointer, nextPointer));
    //
    // byte[] compression = protocolMessage.getCompressions().getValue();
    // tlsContext.setCompressionMethod(CompressionMethod.getCompressionMethod(compression[0]));
    // tlsContext.setClientSupportedCompressions(CompressionMethod.getCompressionMethods(protocolMessage
    // .getCompressions().getValue()));
    // currentPointer = nextPointer;
    // nextPointer = currentPointer + ExtensionByteLength.EXTENSIONS_LENGTH;
    // protocolMessage.setExtensionsLength(ArrayConverter.bytesToInt(Arrays.copyOfRange(message,
    // currentPointer,
    // nextPointer)));
    // boolean extensionPresent = true;
    // if (tlsContext.getHighestClientProtocolVersion() == ProtocolVersion.TLS10
    // || tlsContext.getSelectedProtocolVersion() == ProtocolVersion.DTLS10) {
    // extensionPresent = (currentPointer - pointer) < length;
    // }
    // if (extensionPresent) {
    // currentPointer += ExtensionByteLength.EXTENSIONS_LENGTH;
    // }
    // while ((currentPointer - pointer) <= length) {
    // nextPointer = currentPointer + ExtensionByteLength.TYPE;
    // byte[] extensionType = Arrays.copyOfRange(message, currentPointer,
    // nextPointer);
    // try {
    // ExtensionType type = ExtensionType.getExtensionType(extensionType);
    // ExtensionHandler<? extends ExtensionMessage> eh =
    // type.getExtensionHandler();
    // currentPointer = eh.parseExtension(message, currentPointer);
    // protocolMessage.addExtension(eh.getExtensionMessage());
    // LOGGER.debug(eh.getExtensionMessage().toString());
    // } catch (UnsupportedOperationException ex) {
    // ExtensionHandler<? extends ExtensionMessage> eh = new
    // UnknownExtensionHandler();
    // currentPointer = eh.parseExtension(message, currentPointer);
    // protocolMessage.addExtension(eh.getExtensionMessage());
    // LOGGER.debug(eh.getExtensionMessage().toString());
    // }
    //
    // }
    //
    // protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message,
    // pointer, currentPointer));
    //
    // return (currentPointer - pointer);
    // }

    @Override
    protected Parser getParser(byte[] message, int pointer) {
        return new ClientHelloParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(Message message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    protected Serializer getSerializer(Message message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    protected void adjustTLSContext(Message message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }
}
