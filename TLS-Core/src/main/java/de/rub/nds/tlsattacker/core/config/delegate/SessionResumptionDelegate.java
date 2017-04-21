/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.converters.ByteArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SessionResumptionDelegate extends Delegate {

    @Parameter(names = "-session_resumption", description = "YES or NO")
    private Boolean sessionResumption = null;
    @Parameter(names = "-session_id", description = "The sessionID to resume in hex", converter = ByteArrayConverter.class)
    private byte[] sessionID = null;

    public SessionResumptionDelegate() {
    }

    public Boolean isSessionResumption() {
        return sessionResumption;
    }

    public void setSessionResumption(boolean sessionResumption) {
        this.sessionResumption = sessionResumption;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (sessionResumption != null) {
            config.setSessionResumption(sessionResumption);
        }
        if (sessionID != null) {
            config.setSessionId(sessionID);
        }
    }
}
