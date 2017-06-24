/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class HelloRetryRequestPreparator extends HandshakeMessagePreparator<HelloRetryRequestMessage> {

    private final HelloRetryRequestMessage msg;

    public HelloRetryRequestPreparator(TlsContext context, HelloRetryRequestMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing HelloRetryRequestMessage");
        prepareProtocolVersion();
        prepareCipherSuite();
        prepareExtensions();
        prepareExtensionLength();
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
        LOGGER.debug("SelectedCipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }

}
