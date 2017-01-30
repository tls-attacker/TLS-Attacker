/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.CipherSuiteConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentModuleDelegate extends Delegate {

    /**
     * The agent that should be used
     */
    @Parameter(names = "-agent", description = "The Agent the Fuzzer uses to monitor the application (Default: AFL). Possible: AFL, PIN, BLIND")
    protected String agent = "blind";
    /**
     * If the server should be used with the kill command specified in the
     * server config
     */
    @Parameter(names = "-use_kill", description = "Uses the kill command specified in the server configuration files.")
    private boolean useKill = false;

    /**
     * Timeout for server starts
     */
    @Parameter(names = "-boot_timeout", description = "The maximum time the fuzzer waits till the implementation boots up.")
    private Integer bootTimeout = 50000;
    
    /**
     * If a random port should be used on every server start
     */
    @Parameter(names = "-random_port", description = "Uses random ports for the Server")
    private boolean randomPort = false;

    public AgentModuleDelegate() {
    }

    public String getAgent() {
        return agent;
    }

    public void setAgent(String agent) {
        this.agent = agent;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
    }

}
