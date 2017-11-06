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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.ByteArrayConverter;

public class SessionResumptionDelegate extends Delegate {

    @Parameter(names = "-session_id", description = "The session ID to resume in hex", converter = ByteArrayConverter.class)
    private byte[] sessionId = null;

    public SessionResumptionDelegate() {
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    @Override
    public void applyDelegate(Config config) {
        if (sessionId != null) {
            config.setDefaultClientSessionId(sessionId);
            config.setDefaultServerSessionId(sessionId);
        }
    }
}
