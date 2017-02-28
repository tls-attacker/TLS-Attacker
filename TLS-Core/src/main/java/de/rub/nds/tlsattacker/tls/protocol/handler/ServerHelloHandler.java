/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.UnknownCiphersuiteException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ServerHelloMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ServerHelloMessageSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.Time;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloMessage.class);

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    //
    //
    // @Override
    // public byte[] prepareMessageAction() {
    // ServerHelloMessage message = new
    // ServerHelloMessage(tlsContext.getConfig());
    // ServerHelloMessagePreparator preparator = new
    // ServerHelloMessagePreparator(tlsContext, message);
    // preparator.prepare();
    // adjustTLSContext(message);
    // ServerHelloMessageSerializer serializer = new
    // ServerHelloMessageSerializer(message);
    // message.setCompleteResultingMessage(serializer.serialize());
    // return message.getCompleteResultingMessage().getValue();
    // }
    // ProtocolVersion ourVersion =
    // tlsContext.getConfig().getHighestProtocolVersion();
    // ProtocolVersion clientVersion =
    // tlsContext.getHighestClientProtocolVersion();
    // int intRepresentationOurVersion = ourVersion.getValue()[0] * 0x100 +
    // ourVersion.getValue()[1];
    // int intRepresentationClientVersion = clientVersion.getValue()[0] * 0x100
    // + clientVersion.getValue()[1];
    // if (tlsContext.getConfig().isEnforceSettings()) {
    // tlsContext.setSelectedProtocolVersion(ourVersion);
    // } else {
    // if (tlsContext.getHighestClientProtocolVersion().isDTLS()
    // && tlsContext.getConfig().getHighestProtocolVersion().isDTLS()) {
    // // We both want dtls
    // if (intRepresentationClientVersion <= intRepresentationOurVersion) {
    // tlsContext.setSelectedProtocolVersion(ourVersion);
    // } else {
    // tlsContext.setSelectedProtocolVersion(clientVersion);
    // }
    // }
    // if (!tlsContext.getHighestClientProtocolVersion().isDTLS()
    // && !tlsContext.getConfig().getHighestProtocolVersion().isDTLS()) {
    // // We both want tls
    // if (intRepresentationClientVersion >= intRepresentationOurVersion) {
    // tlsContext.setSelectedProtocolVersion(ourVersion);
    // } else {
    // tlsContext.setSelectedProtocolVersion(clientVersion);
    // }
    // } else {
    // // We dont want to speak the same Protocol
    // // TODO perhaps fuzzing mode option
    // throw new ConfigurationException("TLS/DTLS Mismatch");
    // }
    // }
    // if (tlsContext.getConfig().isEnforceSettings()) {
    // tlsContext.setSelectedCipherSuite(tlsContext.getConfig().getSupportedCiphersuites().get(0));
    // } else {
    // CipherSuite selectedSuite = null;
    // for (CipherSuite suite :
    // tlsContext.getConfig().getSupportedCiphersuites()) {
    // if (tlsContext.getClientSupportedCiphersuites().contains(suite)) {
    // selectedSuite = suite;
    // break;
    // }
    // }
    // tlsContext.setSelectedCipherSuite(selectedSuite);
    // // TODO fuzzing mode
    // if (selectedSuite == null) {
    // throw new ConfigurationException("No Ciphersuites in common");
    // }
    // }
    // protocolMessage.setProtocolVersion(tlsContext.getSelectedProtocolVersion().getValue());
    //
    // // supporting Session Resumption with Session IDs
    // if (tlsContext.getConfig().isSessionResumption()) {
    // protocolMessage.setSessionId(tlsContext.getConfig().getSessionId());
    // } else {
    // // since the server cannot handle more than one Client at once a
    // // static Session-ID is set
    // protocolMessage.setSessionId(ArrayConverter
    // .hexStringToByteArray("f727d526b178ecf3218027ccf8bb125d572068220000ba8c0f774ba7de9f5cdb"));
    // tlsContext.setSessionID(protocolMessage.getSessionId().getValue());
    // }
    // int length = protocolMessage.getSessionId().getValue().length;
    // protocolMessage.setSessionIdLength(length);
    // // random handling
    // final long unixTime = Time.getUnixTime();
    // protocolMessage.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));
    // byte[] random = new byte[HandshakeByteLength.RANDOM];
    // RandomHelper.getRandom().nextBytes(random);
    // protocolMessage.setRandom(random);
    // tlsContext.setServerRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(),
    // protocolMessage
    // .getRandom().getValue()));
    // CipherSuite selectedCipherSuite = tlsContext.getSelectedCipherSuite();
    // protocolMessage.setSelectedCipherSuite(selectedCipherSuite.getByteValue());
    // tlsContext.initiliazeTlsMessageDigest();
    // if (tlsContext.getConfig().isEnforceSettings()) {
    // tlsContext.setCompressionMethod(tlsContext.getConfig().getSupportedCompressionMethods().get(0));
    // } else {
    // CompressionMethod selectedCompressionMethod = null;
    // for (CompressionMethod method :
    // tlsContext.getConfig().getSupportedCompressionMethods()) {
    // if (tlsContext.getClientSupportedCompressions().contains(method)) {
    // selectedCompressionMethod = method;
    // break;
    // }
    // }
    // tlsContext.setCompressionMethod(selectedCompressionMethod);
    // // TODO fuzzing mode
    // if (selectedCompressionMethod == null) {
    // throw new WorkflowExecutionException("No Compression in common");
    // }
    // }
    // protocolMessage.setSelectedCompressionMethod(tlsContext.getCompressionMethod().getValue());
    //
    // byte[] result =
    // ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(),
    // protocolMessage
    // .getUnixTime().getValue(), protocolMessage.getRandom().getValue(),
    // ArrayConverter.intToBytes(
    // protocolMessage.getSessionIdLength().getValue(), 1),
    // protocolMessage.getSessionId().getValue(),
    // protocolMessage.getSelectedCipherSuite().getValue(), new
    // byte[]{protocolMessage
    // .getSelectedCompressionMethod().getValue()});
    //
    // // extensions have to be added to the protocol message before the
    // // workflow trace is generated
    // byte[] extensionBytes = null;
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
    //
    // result = ArrayConverter.concatenate(result, extensionLength,
    // extensionBytes);
    // }
    // if (extensionBytes != null) {
    // protocolMessage.setExtensionsLength(extensionBytes.length);
    // } else {
    // protocolMessage.setExtensionsLength(0);
    // }
    // protocolMessage.setLength(result.length);
    //
    // long header = (HandshakeMessageType.SERVER_HELLO.getValue() << 24) +
    // protocolMessage.getLength().getValue();
    //
    // protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
    // ArrayConverter.longToUint32Bytes(header), result));
    //
    // return protocolMessage.getCompleteResultingMessage().getValue();

    @Override
    protected Preparator getPreparator(ServerHelloMessage message) {
        return new ServerHelloMessagePreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(ServerHelloMessage message) {
        return new ServerHelloMessageSerializer(message);
    }

    @Override
    protected Parser getParser(byte[] message, int pointer) {
        return new ServerHelloParser(pointer, message);
    }

    @Override
    protected void adjustTLSContext(ServerHelloMessage message) {
        tlsContext.setSelectedCipherSuite(CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue()));
        tlsContext.setServerRandom(message.getRandom().getValue());
        tlsContext.setCompressionMethod(CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod()
                .getValue()));
        tlsContext.setSessionID(message.getSessionId().getValue());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.getProtocolVersion(message.getProtocolVersion()
                .getValue()));
        for (ExtensionMessage extension : message.getExtensions()) {
            throw new UnsupportedOperationException("Get extensionHandlers here and adjust context");
        }
        tlsContext.initiliazeTlsMessageDigest();
    }
}
