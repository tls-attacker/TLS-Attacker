/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.Time;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloMessagePreparator<T extends ServerHelloMessage> extends HelloMessagePreparator<HelloMessage> {

    private final ServerHelloMessage message;

    public ServerHelloMessagePreparator(TlsContext context, ServerHelloMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        prepareProtocolVersion();
        prepareUnixTime();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();
        prepareCipherSuite();
        prepareCompressionMethod();
        prepareExtensions();
        prepareExtensionLength();
        prepareMessageLength(0);

    }

    private void prepareCipherSuite() {
        if (context.getConfig().isEnforceSettings()) {
            message.setSelectedCipherSuite(context.getConfig().getSupportedCiphersuites().get(0).getByteValue());
        } else {
            CipherSuite selectedSuite = null;
            for (CipherSuite suite : context.getConfig().getSupportedCiphersuites()) {
                if (context.getClientSupportedCiphersuites().contains(suite)) {
                    selectedSuite = suite;
                    break;
                }
            }
            if (selectedSuite == null) {
                throw new WorkflowExecutionException("No Ciphersuites in common");
            }
            message.setSelectedCipherSuite(selectedSuite.getByteValue());
        }
    }

    private void prepareCompressionMethod() {
        if (context.getConfig().isEnforceSettings()) {
            message.setSelectedCompressionMethod(context.getConfig().getSupportedCompressionMethods().get(0).getValue());
        } else {
            CompressionMethod selectedCompressionMethod = null;
            for (CompressionMethod method : context.getConfig().getSupportedCompressionMethods()) {
                if (context.getClientSupportedCompressions().contains(method)) {
                    selectedCompressionMethod = method;
                    break;
                }
            }
            if (selectedCompressionMethod == null) {
                throw new WorkflowExecutionException("No Compression in common");
            }
            message.setSelectedCompressionMethod(selectedCompressionMethod.getValue());

        }
    }

    private void prepareRandom() {
        byte[] random = new byte[HandshakeByteLength.RANDOM];
        RandomHelper.getRandom().nextBytes(random);
        message.setRandom(random);
    }

    private void prepareUnixTime() {
        final long unixTime = Time.getUnixTime();
        message.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));
    }

    private void prepareSessionIDLength() {
        message.setSessionIdLength(message.getSessionId().getOriginalValue().length);
    }

    private void prepareSessionID() {
        if (context.getConfig().getSessionId().length > 0) {
            message.setSessionId(context.getConfig().getSessionId());
        } else {
            message.setSessionId(ArrayConverter
                    .hexStringToByteArray("f727d526b178ecf3218027ccf8bb125d572068220000ba8c0f774ba7de9f5cdb"));
        }
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = context.getConfig().getHighestProtocolVersion();
        ProtocolVersion clientVersion = context.getHighestClientProtocolVersion();
        int intRepresentationOurVersion = ourVersion.getValue()[0] * 0x100 + ourVersion.getValue()[1];
        int intRepresentationClientVersion = clientVersion.getValue()[0] * 0x100 + clientVersion.getValue()[1];
        if (context.getConfig().isEnforceSettings()) {
            message.setProtocolVersion(ourVersion.getValue());
        } else {
            if (context.getHighestClientProtocolVersion().isDTLS()
                    && context.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want dtls
                if (intRepresentationClientVersion <= intRepresentationOurVersion) {
                    message.setProtocolVersion(ourVersion.getValue());
                } else {
                    message.setProtocolVersion(clientVersion.getValue());
                }
            }
            if (!context.getHighestClientProtocolVersion().isDTLS()
                    && !context.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want tls
                if (intRepresentationClientVersion >= intRepresentationOurVersion) {
                    message.setProtocolVersion(ourVersion.getValue());
                } else {
                    message.setProtocolVersion(clientVersion.getValue());
                }
            } else {
                if (context.getConfig().isFuzzingMode()) {
                    message.setProtocolVersion(ourVersion.getValue());
                } else {
                    throw new WorkflowExecutionException("TLS/DTLS Mismatch");
                }
            }
        }
    }

    private void prepareExtensions() {
        for (ExtensionMessage extensionMessage : message.getExtensions()) {

        }
    }

    private void prepareExtensionLength() {
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
