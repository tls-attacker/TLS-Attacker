/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSDelegateConfig {

    private final List<Delegate> delegateList;
    private final GeneralDelegate generalDelegate;

    public TLSDelegateConfig() {
        delegateList = new LinkedList<>();
        generalDelegate = new GeneralDelegate();
        delegateList.add(generalDelegate);
    }

    public void addDelegate(Delegate delegate) {
        delegateList.add(delegate);
    }

    public List<Delegate> getDelegateList() {
        return Collections.unmodifiableList(delegateList);
    }

    public GeneralDelegate getGeneralDelegate() {
        return generalDelegate;
    }

    public TlsConfig createConfig() {
        TlsConfig config = new TlsConfig();
        for (Delegate delegate : getDelegateList()) {
            delegate.applyDelegate(config);
        }
        return config;
    }

}
