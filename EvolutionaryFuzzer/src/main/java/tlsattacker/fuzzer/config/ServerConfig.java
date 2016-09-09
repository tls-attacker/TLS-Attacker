/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.beust.jcommander.validators.PositiveInteger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Parameters(commandDescription = "Generates a new Server Config file")
public class ServerConfig {

    @Parameter(names = "-ip", required = false, description = "IP of the Server")
    private String ip = "127.0.0.1";
    @Parameter(names = "-port", required = false, description = "Port of the Server", validateWith = PositiveInteger.class)
    private int port = 4433;
    @Parameter(names = "-accept", required = true, description = "The String the Server outputs when it finished booting")
    private String accept;
    @Parameter(names = "-start", required = true, description = "The command with which the Server is started. Can use placeholders:\n\t\t[cert] certificate used by the Server\n\t\t[key] private key used by the Server\n\t\t[port] port used by the Server")
    private String startcommand;
    @Parameter(names = "-output", required = true, description = "The File in which the Server is serialized to")
    private String output;
    @Parameter(names = "-killCommand", required = false, description = "The Command needed to kill the Server after each execution, probably makes only sense in a single Threaded enviroment")
    private String killCommand;

    public String getIp() {
	return ip;
    }

    public void setIp(String ip) {
	this.ip = ip;
    }

    public String getKillCommand() {
	return killCommand;
    }

    public int getPort() {
	return port;
    }

    public void setPort(int port) {
	this.port = port;
    }

    public String getAccept() {
	return accept;
    }

    public void setAccept(String accept) {
	this.accept = accept;
    }

    public String getStartcommand() {
	return startcommand;
    }

    public void setStartcommand(String startcommand) {
	this.startcommand = startcommand;
    }

    public String getOutput() {
	return output;
    }

    public void setOutput(String output) {
	this.output = output;
    }

}
