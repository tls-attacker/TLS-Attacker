
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Currently only Implementation of the Controller Interface which controls the
 * complete executions
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerController extends Controller
{
    private static final Logger LOG = Logger.getLogger(FuzzerController.class.getName());

    //Chosen Mutator
    private final Mutator mutator;
    //ThreadPool to start or stop
    private final ExecutorThreadPool pool;

    /**
     * Basic Constructor, initializes the Server List, generates the necessary
     * Config Files and Contexts and also commints to a mutation Engine
     */
    public FuzzerController()
    {
        ServerManager serverManager = ServerManager.getInstance();
        for (File f : new File("server/").listFiles())
        {
            try
            {
                TLSServer server = ServerSerializer.read(f);
                serverManager.addServer(server);

            }
            catch (Exception ex)
            {
                LOG.log(Level.SEVERE, "Could not read Server!", ex);
            }
        }

        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        TlsContext tmpTlsContext = configHandler.initializeTlsContext(new EvolutionaryFuzzerConfig());
        mutator = new SimpleMutator(tmpTlsContext);
        pool = new ExecutorThreadPool(1, mutator);
        Thread t = new Thread(pool);
        t.setName("Executor Thread Pool");
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

}
