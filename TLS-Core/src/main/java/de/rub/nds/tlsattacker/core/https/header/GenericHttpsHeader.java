/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header;

import de.rub.nds.tlsattacker.core.https.header.preparator.GenericHttpsHeaderPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GenericHttpsHeader extends HttpsHeader {

    private String headerNameConfig;

    private String headerValueConfig;

    public GenericHttpsHeader() {
    }

    public GenericHttpsHeader(String headerNameConfig, String headerValueConfig) {
        this.headerNameConfig = headerNameConfig;
        this.headerValueConfig = headerValueConfig;
    }

    public String getHeaderNameConfig() {
        return headerNameConfig;
    }

    public void setHeaderNameConfig(String headerNameConfig) {
        this.headerNameConfig = headerNameConfig;
    }

    public String getHeaderValueConfig() {
        return headerValueConfig;
    }

    public void setHeaderValueConfig(String headerValueConfig) {
        this.headerValueConfig = headerValueConfig;
    }

    @Override
    public Preparator getPreparator(Chooser chooser) {
        return new GenericHttpsHeaderPreparator(chooser, this);
    }
}
