/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.logging.Logger;

/**
 * Currently only Implementation of the Controller Interface which controls the
 * complete executions
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerController extends Controller
{
    //Chosen Mutator
    private final Mutator mutator;
    //ThreadPool to start or stop
    private final ExecutorThreadPool pool;

    /**
     *  Basic Constructor, initializes the Server List, generates the necessary Config Files and Contexts and also commints to a mutation Engine
     */
    public FuzzerController()
    {
        ServerManager serverManager = ServerManager.getInstance();
        //TODO StartCommand Insert
        serverManager.addServer(new TLSServer("127.0.0.1", 4433, "/home/ic0ns/Downloads/afl/afl-2.10b/afl-showmap -m none -o /home/ic0ns/Traces/openssl[id] /home/ic0ns/Downloads/afl/afl-2.10b/openssl-1.1.0-pre5/myOpenssl/bin/openssl s_server -naccept 1 -key /home/ic0ns/key.pem -cert /home/ic0ns/cert.pem -accept 4433","ACCEPT"));
        //This is akward
        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        TlsContext tmpTlsContext = configHandler.initializeTlsContext(new EvolutionaryFuzzerConfig());
        mutator = new SimpleMutator(tmpTlsContext);
        pool = new ExecutorThreadPool(1, mutator);
        Thread t = new Thread(pool);
        t.start();
    }

    /**
     * Starts the Fuzzer
     */
    @Override
    public void startFuzzer()
    {
        this.isRunning = false;
        pool.setStopped(false);
    }

    /**
     * Stops the Fuzzer
     */
    @Override
    public void stopFuzzer()
    {
        this.isRunning = false;
        pool.setStopped(true);
    }
    private static final Logger LOG = Logger.getLogger(FuzzerController.class.getName());

}
