/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.agent;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class AFLAgentConfig implements Serializable {
    
    /**
     * Path to the AFL folder
     */
    private String pathToAFL = "AFL/";
    
    /**
     * Size of the AFL bitmap, normally set to 1 << 16
     */
    private int bitmapSize = 1<<16;

    public AFLAgentConfig() {
    }

    public String getPathToAFL() {
        return pathToAFL;
    }

    public void setPathToAFL(String pathToAFL) {
        this.pathToAFL = pathToAFL;
    }

    public int getBitmapSize() {
        return bitmapSize;
    }

    public void setBitmapSize(int bitmapSize) {
        this.bitmapSize = bitmapSize;
    }
    
}
