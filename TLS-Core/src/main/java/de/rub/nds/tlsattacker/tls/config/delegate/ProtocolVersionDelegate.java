/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.ProtocolVersionConverter;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionDelegate extends Delegate {

    @Parameter(names = "-version", description = "Protocol version to use", converter = ProtocolVersionConverter.class)
    private ProtocolVersion protocolVersion = ProtocolVersion.TLS12;

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
        config.setProtocolVersion(protocolVersion);
    }

}
