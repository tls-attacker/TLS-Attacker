/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.custom.tls.server.config;

import com.beust.jcommander.Parameter;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MitmConfig {

    public static final String ATTACK_COMMAND = "mitm";

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints help")
    protected boolean help;

    @Parameter(names = "-port", description = "The port MITM server is running on")
    protected Integer port = 8443;

    @Parameter(names = "-connect", description = "Who to connect to (the victim server)")
    protected String connect = "localhost:4433";

    @Parameter(names = "-delay", description = "Delay between bytes sent to the client, while sending the server certificate (in millis).")
    protected Integer delay = 80;

    @Parameter(names = "-max_transport_response_wait", description = "Maximum time in milliseconds to wait for peer's response.")
    protected Integer maxTransportResponseWait = 50;

    @Parameter(names = { "-split_certificate" }, description = "Split certificate into bytes and send them in separated records (works against most of the browsers)")
    protected boolean splitCertificate;

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }

    public Integer getPort() {
	return port;
    }

    public void setPort(Integer port) {
	this.port = port;
    }

    public String getConnect() {
	return connect;
    }

    public void setConnect(String connect) {
	this.connect = connect;
    }

    public Integer getDelay() {
	return delay;
    }

    public void setDelay(Integer delay) {
	this.delay = delay;
    }

    public Integer getMaxTransportResponseWait() {
	return maxTransportResponseWait;
    }

    public void setMaxTransportResponseWait(Integer maxTransportResponseWait) {
	this.maxTransportResponseWait = maxTransportResponseWait;
    }

    public boolean isSplitCertificate() {
	return splitCertificate;
    }

    public void setSplitCertificate(boolean splitCertificate) {
	this.splitCertificate = splitCertificate;
    }
}
