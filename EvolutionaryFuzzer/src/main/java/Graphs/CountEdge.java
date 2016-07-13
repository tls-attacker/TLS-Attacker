/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Graphs;

import java.util.logging.Logger;

public class CountEdge extends org.jgrapht.graph.DefaultEdge {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = Logger.getLogger(CountEdge.class.getName());
    // Branch Counter
    private int count = 1;

    /**
     * Default Constructor
     */
    public CountEdge() {
    }

    /**
     * Increments the counter
     */
    public void increment() {
	count++;
    }

    public void add(int count) {
	this.count += count;
    }

    /**
     * Returns the Count value of the Edge
     * 
     * @return Count value of the Edge
     */
    public int getCount() {
	return count;
    }
}
