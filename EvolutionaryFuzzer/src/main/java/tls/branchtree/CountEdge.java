/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tls.branchtree;

import java.util.logging.Logger;

/**
 * This Class represents a basic Counter for the Graphs. The Counter indicates
 * how often a Branch from Source to Destination was taken. The Counter is
 * initialized with 1
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CountEdge extends org.jgrapht.graph.DefaultEdge
{

    private static final long serialVersionUID = 1L;
    //Branch Counter
    private int count = 1;

    /**
     * Default Constructor
     */
    public CountEdge()
    {
    }

    /**
     * Increments the counter
     */
    public void increment()
    {
        count++;
    }

    /**
     * Returns the Count value of the Edge
     *
     * @return Count value of the Edge
     */
    public int getCount()
    {
        return count;
    }
    private static final Logger LOG = Logger.getLogger(CountEdge.class.getName());
}
