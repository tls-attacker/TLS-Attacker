/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An Agent implemented with the modified Binary Instrumentation used by
 * American Fuzzy Lop
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class BasicAFLAgent extends Agent
{

    //Is a fuzzing Progress Running?
    protected boolean running = false;
    //StartTime of the last Fuzzing Vektor
    protected long startTime;
    //StopTime of the last Fuzzing Vektor
    protected long stopTime;
    //If the Application did Timeout
    protected boolean timeout;
    //If the Application did Crash
    protected boolean crash;

    /**
     * Default Constructor
     */
    public BasicAFLAgent()
    {
        timeout = false;
        crash = false;

    }

    @Override
    public void onApplicationStart()
    {
        if (running)
        {
            throw new IllegalStateException("Cannot start a running AFL Agent");
        }
        startTime = System.currentTimeMillis();
        running = true;
    }

    @Override
    public void onApplicationStop()
    {
        if (!running)
        {
            throw new IllegalStateException("Cannot stop a stopped AFL Agent");
        }
        stopTime = System.currentTimeMillis();
        running = false;
    }

    @Override
    public Result collectResults(File branchTrace, WorkflowTrace trace)
    {
        //TODO change exception Type.
        if (running)
        {
            throw new IllegalStateException("Can't collect Results, Agent still running!");
        }

        String tail = tail(branchTrace);
        if (tail.equals("CRASH"))
        {
            LOG.log(Level.INFO, "Found a Crash!");
            crash = true;
        }
        else if (tail.equals("TIMEOUT"))
        {
            LOG.log(Level.INFO, "Found a Timeout!");
            timeout = true;
        }
        Result result = new Result(crash, timeout, startTime, stopTime, branchTrace, trace,LogFileIDManager.getInstance().getID());

        return result;
    }

    private String tail(File file)
    {
        RandomAccessFile fileHandler = null;
        try
        {
            fileHandler = new RandomAccessFile(file, "r");
            long fileLength = fileHandler.length() - 1;
            StringBuilder sb = new StringBuilder();

            for (long filePointer = fileLength; filePointer != -1; filePointer--)
            {
                fileHandler.seek(filePointer);
                int readByte = fileHandler.readByte();

                if (readByte == 0xA)
                {
                    if (filePointer == fileLength)
                    {
                        continue;
                    }
                    break;

                }
                else if (readByte == 0xD)
                {
                    if (filePointer == fileLength - 1)
                    {
                        continue;
                    }
                    break;
                }

                sb.append((char) readByte);
            }

            String lastLine = sb.reverse().toString();
            return lastLine;
        }
        catch (java.io.FileNotFoundException e)
        {
            e.printStackTrace();
            return null;
        }
        catch (java.io.IOException e)
        {
            e.printStackTrace();
            return null;
        }
        finally
        {
            if (fileHandler != null)
            {
                try
                {
                    fileHandler.close();
                }
                catch (IOException e)
                {
                    /* ignore */
                }
            }
        }
    }
    private static final Logger LOG = Logger.getLogger(BasicAFLAgent.class.getName());

}
