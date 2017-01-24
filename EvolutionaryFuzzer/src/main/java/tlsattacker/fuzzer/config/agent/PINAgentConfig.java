/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.agent;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class PINAgentConfig implements Serializable {

    /**
     * If the PIN script should inject itself into the Child process
     */
    private boolean injectChild = true;

    /**
     * Path to PIN
     */
    private String pathToPin = "PIN/";

    public PINAgentConfig() {
    }

    public boolean isInjectChild() {
        return injectChild;
    }

    public void setInjectChild(boolean injectChild) {
        this.injectChild = injectChild;
    }

    public String getPathToPin() {
        return pathToPin;
    }

    public void setPathToPin(String pathToPin) {
        this.pathToPin = pathToPin;
    }

}
