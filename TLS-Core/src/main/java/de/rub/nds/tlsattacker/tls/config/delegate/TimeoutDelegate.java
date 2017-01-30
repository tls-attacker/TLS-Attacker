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
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TimeoutDelegate extends Delegate {

    @Parameter(names = "-timeout", description = "Timeout for socket connection")
    private int timeout = 1000;

    @Parameter(names = "-tls_timeout", description = "Maximum time in milliseconds to wait for peer's response. Use different values for attack optimizations (e.g. 30 for OpenSSL localhost or 50 for JSSE localhost)")
    private int tlsTimeout = 400;

    public TimeoutDelegate() {
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getTlsTimeout() {
        return tlsTimeout;
    }

    public void setTlsTimeout(int tlsTimeout) {
        this.tlsTimeout = tlsTimeout;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setTlsTimeout(tlsTimeout);
        config.setTimeout(timeout);
    }

}
