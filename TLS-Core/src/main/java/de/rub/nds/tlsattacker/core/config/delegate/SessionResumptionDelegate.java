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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SessionResumptionDelegate extends Delegate {

    @Parameter(names = "-session_id", description = "The sessionID to resume in hex", converter = ByteArrayConverter.class)
    private byte[] sessionID = null;

    public SessionResumptionDelegate() {
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    @Override
    public void applyDelegate(Config config) {
        if (sessionID != null) {
            config.setDefaultClientSessionId(sessionID);
            config.setDefaultServerSessionId(sessionID);
        }
    }
}
