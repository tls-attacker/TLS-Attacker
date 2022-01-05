/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
public abstract class AsciiAction extends TlsAction {

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
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
     *                  the asciiText to set
     */
    public void setAsciiText(String asciiText) {
        this.asciiText = asciiText;
    }

    public String getEncoding() {
        return encoding;
    }
}
