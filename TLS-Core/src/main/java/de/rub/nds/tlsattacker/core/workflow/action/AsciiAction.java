/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

public abstract class AsciiAction extends TlsAction {

    private String asciiText;

    private final String encoding;

    protected AsciiAction() {
        asciiText = null;
        encoding = null;
    }

    public AsciiAction(String asciiText, String encoding) {
        this.asciiText = asciiText;
        this.encoding = encoding;
    }

    public AsciiAction(String encoding) {
        this.asciiText = null;
        this.encoding = encoding;
    }

    /**
     * @return the asciiText
     */
    public String getAsciiText() {
        return asciiText;
    }

    /**
     * @param asciiText
     *            the asciiText to set
     */
    public void setAsciiText(String asciiText) {
        this.asciiText = asciiText;
    }

    public String getEncoding() {
        return encoding;
    }
}
