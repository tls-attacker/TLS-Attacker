/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.IOException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public interface TransportHandler {

    void closeConnection();

    byte[] fetchData() throws IOException;

    void initialize(String address, int port) throws IOException;

    void sendData(byte[] data) throws IOException;

}
