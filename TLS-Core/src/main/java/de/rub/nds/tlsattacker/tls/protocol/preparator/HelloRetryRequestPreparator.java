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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Nurullah Erinola
 */
public class HelloRetryRequestPreparator extends HandshakeMessagePreparator<HelloRetryRequestMessage> {

    private final HelloRetryRequestMessage msg;

    public HelloRetryRequestPreparator(TlsContext context, HelloRetryRequestMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        prepareProtocolVersion();
        prepareCipherSuite();
        prepareExtensionLength();
        prepareExtensions();
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = context.getConfig().getHighestProtocolVersion();
        if (context.getConfig().isEnforceSettings()) {
            msg.setProtocolVersion(ourVersion.getValue());
        } else {
            msg.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    private void prepareCipherSuite() {
        if (context.getConfig().isEnforceSettings()) {
            msg.setSelectedCipherSuite(context.getConfig().getSupportedCiphersuites().get(0).getByteValue());
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
            msg.setSelectedCipherSuite(selectedSuite.getByteValue());
        }
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }

}
