package de.rub.nds.tlsattacker.custom.tls.server;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EllipticCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.custom.tls.server.config.MitmConfig;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    public static Logger LOGGER = LogManager.getLogger(Main.class);

    public static void main(String[] args) throws Exception {

	Security.addProvider(new BouncyCastleProvider());

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	MitmConfig mitmConfig = new MitmConfig();
	jc.addCommand(MitmConfig.ATTACK_COMMAND, mitmConfig);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	ServerSocket serverSocket = new ServerSocket(mitmConfig.getPort());
	LOGGER.info("Starting a server on port {}", mitmConfig.getPort());
	LOGGER.info("Socket Timeout: {}", serverSocket.getSoTimeout());

	Server server = null;

	while (true) {
	    Socket clientSocket = serverSocket.accept();
	    OutputStream out = clientSocket.getOutputStream();
	    InputStream in;
	    in = (clientSocket.getInputStream());
	    if (server == null || !server.isRunning()) {
		server = new Server(mitmConfig, in, out);
		server.start();
	    } else {
		try {
		    LOGGER.info("Current Server thread running, no new connection accepted");
		    in.close();
		    out.close();
		} catch (IOException ex) {
		    LOGGER.info(ex);
		}
	    }
	}
    }
}
