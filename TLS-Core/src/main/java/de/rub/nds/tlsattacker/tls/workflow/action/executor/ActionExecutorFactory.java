/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ActionExecutorFactory {

    public static ActionExecutor getActionExecutor(ExecutorType type, TlsContext context) {
        switch (type) {

            case SSL2:
                return new SSLActionExecutor(context);
            case TLS:
                return new DefaultActionExecutor(context);
            case DTLS:
            default:
                throw new UnsupportedOperationException("ActionExecutor " + type.name() + " not supported");
        }
    }
}
