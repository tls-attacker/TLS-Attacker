/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.converters.ProtocolVersionConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionDelegate extends Delegate {

    @Parameter(names = "-version", description = "Highest supported Protocolversion ", converter = ProtocolVersionConverter.class)
    private ProtocolVersion protocolVersion = null;

    public ProtocolVersionDelegate() {
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (protocolVersion != null) {
            config.setHighestProtocolVersion(protocolVersion);
        }
        if (config.getHighestProtocolVersion().isDTLS()) {
            config.setTransportHandlerType(TransportHandlerType.UDP);
        } else {
            config.setTransportHandlerType(TransportHandlerType.TCP);
        }
    }

}
