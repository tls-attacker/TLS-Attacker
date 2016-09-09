/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.UnknownCiphersuiteException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
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
	this.correctProtocolMessageClass = ServerHelloMessage.class;
    }

    /**
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.SERVER_HELLO.getValue()) {
	    throw new InvalidMessageTypeException("This is not a server hello message");
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

	protocolMessage.setProtocolVersion(Arrays.copyOfRange(message, currentPointer, nextPointer));
	if (serverProtocolVersion == null) {
	    System.out.println("Unknown protocolversion" + ArrayConverter.bytesToHexString(Arrays.copyOfRange(message, currentPointer, nextPointer)));//TODO
	}

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.UNIX_TIME;
	byte[] serverUnixTime = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setUnixTime(serverUnixTime);
	// System.out.println(new
	// Date(ArrayConverter.bytesToLong(serverUnixTime) * 1000));

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.RANDOM;
	byte[] serverRandom = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setRandom(serverRandom);

	tlsContext.setServerRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(), protocolMessage
		.getRandom().getValue()));

	currentPointer = nextPointer;
	int sessionIdLength = message[currentPointer] & 0xFF;
	currentPointer = currentPointer + HandshakeByteLength.SESSION_ID_LENGTH;
	nextPointer = currentPointer + sessionIdLength;
	byte[] sessionId = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setSessionId(sessionId);

	// handle unknown SessionID during Session resumption
	if (tlsContext.isSessionResumption()
		&& !(Arrays.equals(tlsContext.getSessionID(), protocolMessage.getSessionId().getValue()))) {
	    throw new WorkflowExecutionException("Session ID is unknown to the Client");
	}

	tlsContext.setSessionID(sessionId);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.CIPHER_SUITE;
	CipherSuite selectedCipher;
	try {
	    selectedCipher = CipherSuite.getCipherSuite(Arrays.copyOfRange(message, currentPointer, nextPointer));
	} catch (UnknownCiphersuiteException ex) {
	    LOGGER.error(ex.getLocalizedMessage());
	    LOGGER.debug(ex.getLocalizedMessage(), ex);
	    selectedCipher = CipherSuite.TLS_UNKNOWN_CIPHER;
	}
	// System.out.println(selectedCipher);
	protocolMessage.setSelectedCipherSuite(selectedCipher.getByteValue());

	tlsContext.setSelectedCipherSuite(CipherSuite.getCipherSuite(protocolMessage.getSelectedCipherSuite()
		.getValue()));
	tlsContext.setProtocolVersion(serverProtocolVersion);
	tlsContext.initiliazeTlsMessageDigest();

	currentPointer = nextPointer;
	byte compression = message[currentPointer];
	currentPointer += HandshakeByteLength.COMPRESSION;
	protocolMessage.setSelectedCompressionMethod(compression);

	tlsContext.setCompressionMethod(CompressionMethod.getCompressionMethod(protocolMessage
		.getSelectedCompressionMethod().getValue()));

	if ((currentPointer - pointer) < length) {
	    currentPointer += ExtensionByteLength.EXTENSIONS;
	    while ((currentPointer - pointer) < length) {
		nextPointer = currentPointer + ExtensionByteLength.TYPE;
		byte[] extensionType = Arrays.copyOfRange(message, currentPointer, nextPointer);
		// Not implemented/unknown extensions will generate an Exception
		// ...
		try {
		    ExtensionHandler eh = ExtensionType.getExtensionType(extensionType).getExtensionHandler();
		    currentPointer = eh.parseExtension(message, currentPointer);
		    protocolMessage.addExtension(eh.getExtensionMessage());
		} // ... which we catch, then disregard that extension and carry
		  // on.
		catch (Exception ex) {
		    currentPointer = nextPointer;
		    nextPointer += 2;
		    currentPointer += ArrayConverter.bytesToInt(Arrays
			    .copyOfRange(message, currentPointer, nextPointer));
		    nextPointer += 2;
		    currentPointer += 2;
		}
	    }
	}

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, currentPointer));

	return currentPointer;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setProtocolVersion(tlsContext.getProtocolVersion().getValue());

	// supporting Session Resumption with Session IDs
	if (tlsContext.isSessionResumption()) {
	    protocolMessage.setSessionId(tlsContext.getSessionID());
	} else {
	    // since the server cannot handle more than one Client at once a
	    // static Session-ID is set
	    protocolMessage.setSessionId(ArrayConverter
		    .hexStringToByteArray("f727d526b178ecf3218027ccf8bb125d572068220000ba8c0f774ba7de9f5cdb"));
	    tlsContext.setSessionID(protocolMessage.getSessionId().getValue());
	}
	int length = protocolMessage.getSessionId().getValue().length;
	protocolMessage.setSessionIdLength(length);

	// random handling
	final long unixTime = Time.getUnixTime();
	protocolMessage.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));

	byte[] random = new byte[HandshakeByteLength.RANDOM];
	RandomHelper.getRandom().nextBytes(random);
	protocolMessage.setRandom(random);

	tlsContext.setServerRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(), protocolMessage
		.getRandom().getValue()));

	CipherSuite selectedCipherSuite = tlsContext.getSelectedCipherSuite();
	protocolMessage.setSelectedCipherSuite(selectedCipherSuite.getByteValue());
	tlsContext.initiliazeTlsMessageDigest();

	CompressionMethod selectedCompressionMethod = tlsContext.getCompressionMethod();
	protocolMessage.setSelectedCompressionMethod(selectedCompressionMethod.getValue());

	byte[] result = ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(), protocolMessage
		.getUnixTime().getValue(), protocolMessage.getRandom().getValue(), ArrayConverter.intToBytes(
		protocolMessage.getSessionIdLength().getValue(), 1), protocolMessage.getSessionId().getValue(),
		protocolMessage.getSelectedCipherSuite().getValue(), new byte[] { protocolMessage
			.getSelectedCompressionMethod().getValue() });

	// extensions have to be added to the protocol message before the
	// workflow trace is generated
	byte[] extensionBytes = null;
	for (ExtensionMessage extension : protocolMessage.getExtensions()) {
	    ExtensionHandler handler = extension.getExtensionHandler();
	    handler.initializeClientHelloExtension(extension);
	    extensionBytes = ArrayConverter.concatenate(extensionBytes, extension.getExtensionBytes().getValue());
	}

	if (extensionBytes != null && extensionBytes.length != 0) {
	    byte[] extensionLength = ArrayConverter.intToBytes(extensionBytes.length, ExtensionByteLength.EXTENSIONS);

	    result = ArrayConverter.concatenate(result, extensionLength, extensionBytes);
	}

	protocolMessage.setLength(result.length);

	long header = (HandshakeMessageType.SERVER_HELLO.getValue() << 24) + protocolMessage.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }
}
