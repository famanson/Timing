package cbc_prac;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class CBCPrac
{

    public static void main(String[] args) 
    {
		// intercepted IV and cipherblock
    	
    	int[] iv = { 0x9b, 0x08, 0x77, 0x04, 0xbf, 0x3f, 0x95, 0x6c }; int[] c = { 0x02, 0x80, 0xd0, 0xd3, 0xf7, 0xfc, 0xe7, 0x2e };
    	
		//int[] iv = { 0xbe, 0x68, 0x7d, 0xc4, 0x21, 0x7a, 0xb4, 0xbe }; int[] c = { 0xe5, 0x9d, 0x70, 0xcf, 0xf1, 0x91, 0x2b, 0xf6 };
		
		//int[] iv = { 0x01, 0x1d, 0x0c, 0xb4, 0x3c, 0x3c, 0xf4, 0xda }; int[] c = { 0xc0, 0x29, 0xa4, 0x5d, 0xff, 0x6b, 0x03, 0x6d };	
		
		
		// we are using the same variable names as in the practical manual
		// except d'=d_
		
		// place here the recovered plaintext
		int[] m=new int[8];
	
		// determines the length of the random message sent to the server
		int n = 127; //because it gives the best time difference
	
		// the only argument is the port number to connect to
		//int port= Integer.parseInt(args[0]);
		int port = 1024;
	
		// find the average response time for 8n+8 byte random blocks
		long timeAverage=doTimeAverage(port, 8*n+8);
		System.out.println("Average server response time = " + timeAverage + "ms");
		// OK, now we can discard slow replies (2*timeAverage will do) 
		// so they don't mess up the timings
	
		breakEncryption(n, c, iv, m, port, timeAverage);
		
		/**
		    Average server response time = 483ms
			r8n = 225 stood out from other values after 87 tries
			m[8] is: 140 (hex: 8c)
			r8n-1 = 231 stood out from other values after 51 tries
			m[7] is: 112 (hex: 70)
			r8n-2 = 52 stood out from other values after 51 tries
			m[6] is: 8 (hex: 8)
			r8n-3 = 164 stood out from other values after 51 tries
			m[5] is: 31 (hex: 1f)
			r8n-4 = 77 stood out from other values after 53 tries
			m[4] is: 76 (hex: 4c)
			r8n-5 = 150 stood out from other values after 51 tries
			m[3] is: 231 (hex: e7)
			r8n-6 = 188 stood out from other values after 51 tries
			m[2] is: 179 (hex: b3)
			r8n-7 = 25 stood out from other values after 51 tries
			m[1] is: 138 (hex: 8a)
			
			The message is: 0x8ab3e74c1f08708c

		*/
    }


    // sends 1000 random messages of length "length", and computes the 
    // average response time
    static long doTimeAverage(int port, int length)
    {
    	Random prng = new Random();
    	long total = 0;
    	for(int i = 0; i < 1000; i++)
    	{
    		byte[] randomMessage = new byte[length];
   			prng.nextBytes(randomMessage);
   			total += doTimeConnection(port, randomMessage, length);
    	}
    	return total/1000;
    }
    
    static void breakEncryption(int n, int[] c, int[] iv, int[] m, int port, long average)
    {
    	List<Integer> toFix;
    	List<Integer> d_ = new ArrayList<Integer>();
    	for (int i = 0; i < 8; i++)
    	{
    		byte[] message = new byte[8*n+8];
    		//padding value to fix = i+1, get the list of fixed r
    		toFix = findFixes(i+1, d_);
    		int newR = findR(toFix, message, n, c, port, average);
    		int newD_ = (i+1)^newR;
    		d_.add(newD_);
    		m[7-i] = newD_^iv[7-i];
    		System.out.println("m[" + (8-i) + "] is: " + m[7-i] + " (hex: " + Long.toHexString(m[7-i]) + ")");
    	}
    	
    	long value = 0;
    	for (int i = 0; i < m.length; i++)
    	{
    	   value = (value << 8) + (m[i] & 0xff);
    	}
    	System.out.println();
    	System.out.println("The message is: 0x" + Long.toHexString(value));
    }
    
    static List<Integer> findFixes(int d, List<Integer> d_)
    {
    	List<Integer> toFix = new ArrayList<Integer>(); 
    	for (int i = 0; i < d_.size(); i++)
    	{
    		toFix.add(d_.get(i)^d);
    	}
    	return toFix;
    }
    
    static int findR(List<Integer> toFix, byte[] message, int n, int[] c, int port, long average)
    {
    	//System.out.println(toFix.toString());
    	Map<Integer,Integer> maxAveragesFrequency = new HashMap<Integer,Integer>();
    	//int length = 8*n+8;
    	long[][] rsTime = new long[256][100];
    	Random prng = new Random();
    	
    	//init the time list
    	for (int i = 0; i < rsTime.length; i++)
    	{
    		for (int j = 0; j < rsTime[i].length; j++)
    		{
    			rsTime[i][j] = 0;
    		}
    	}
    	
    	for (int tries = 0; tries < 100; tries++)
    	{
    		long[] averageOf = new long[256];
	    	int r = 0;
	    	while (r < 256)
	    	{
	    		//make bytes random
	    		prng.nextBytes(message);
	    		
	    		//add the fixed part
	    		for(int fixedLength = 0; fixedLength < toFix.size(); fixedLength++)
	    			message[8*n - fixedLength -1] = toFix.get(fixedLength).byteValue();
	    		
	    		//add the varied part
	    		message[8*n - toFix.size() -1] = (byte) r;
	    		
	    		//add the cipher
	    		for (int l = 0; l < 8; l++)
	    		{
	    			message[8*n+l] = (byte) c[l];
	    		}
	    		
	    		long time = doTimeConnection(port, message, 8*n+8);
	    		if (time <= 2*average)
	    			rsTime[r][tries] = time;
	    		
	    		averageOf[r] = average(rsTime[r]);
	    		//System.out.println(r + " " + averageOf[r]);
	    		r++;
	    	}
	    	
	    	long averageAverage = average(averageOf);
	    	long maxAverage = 0;
	    	int mIndex = 0;
	    	for (int i = 0; i < averageOf.length; i++)
	    	{
	    		long aver = averageOf[i];
	    		if (aver > maxAverage)
	    		{
	    			maxAverage = aver;
	    			mIndex = i;
	    		}
	    	}
	    	if (maxAveragesFrequency.containsKey(mIndex)) 
	    		maxAveragesFrequency.put(mIndex, maxAveragesFrequency.get(mIndex) + 1);
	    	else
	    		maxAveragesFrequency.put(mIndex, 1);
	    	
	    	//Trial-and-error for the difference of 10ms, because just taking the maximum may go 
	    	//into slow-response problems from the OS
	    	if (maxAverage - averageAverage > 10 & tries > 50 & maxAveragesFrequency.get(mIndex) >= tries/2) 
    		{
	    		String toPrint = ((toFix.size() == 0) ? "r8n" : ("r8n-" + toFix.size())) + " = "+ mIndex 
	    			+ " stood out from other values after " + tries + " tries";
	    		System.out.println(toPrint);
    			return mIndex;
    		}
    	}
    	
    	int j = 0;
    	long max = 0;
    	for (int i = 0; i < maxAveragesFrequency.size() & maxAveragesFrequency.containsKey(i); i++)
    	{
    		//long resultAverage = average(rsTime[i]);
    		int resultAverage = maxAveragesFrequency.get(i); 
    		if (resultAverage > max) 
			{
    			max = resultAverage;
    			j = i;
			}
    	}
    	/*long max = 0;
    	for (int i = 0; i < rsTime.length; i++)
    	{
    		long resultAverage = average(rsTime[i]);
    		if (resultAverage > max) 
			{
    			max = resultAverage;
    			j = i;
			}
    	}*/
    	String toPrint = ((toFix.size() == 0) ? "r8n" : ("r8n-" + toFix.size())) + " = "+ j 
    		+ " stood out from other values after 100 tries, topping the table: " 
    		+ maxAveragesFrequency.get(j) + " times.";
    	System.out.println(toPrint);
    	return j;
    }
    
    static long average(long...array)
    {
    	long[] clone = array.clone();
    	long total = 0;
    	long count = 0;
    	for (long element : clone)
    	{
    		if (element > 0)
    		{
    			total+=element;
    			count++;
    		}
    	}
    	if (count > 0)
    		return total/count;
    	else return 0;
    }
    
    // connects to the specific port, writes data, and times how long it takes
    // for the connection to be closed
    // (does not bother to record the server's response, it's uninformative)
    // NB: this code is horrible, and it will hang if the server never responds
    
    static long doTimeConnection(int port, byte[] data, int len)
    { 
        Socket Socket = null;  
        DataOutputStream Out = null;
        DataInputStream In = null;
		long timeStart=0;
		long timeEnd=0;
	
		do // keep repeating until we get a response (will hang if we don't)
		{
		    try 
		    {
				timeStart = System.nanoTime();
		
				// set up the connection with the server
				Socket = new Socket("127.0.0.1", port);
				Out = new DataOutputStream(Socket.getOutputStream());
				In = new DataInputStream(Socket.getInputStream());
		
				Out.write(data, 0, len);    
				// we don't need to do anything with the response, just ignore it
				String response;
				while((response =In.readLine()) != null)
				{
				    //System.err.println(response);
				}
		
				timeEnd=System.nanoTime();
		    }
		    catch (UnknownHostException e) 
		    {
		    	System.err.println("This should never happen: UnknownHostException: " + e);
		    } 
		    catch (IOException e)
		    {
		    	// just ignore IOExceptions (server dropped connection, broken pipes etc)
		    }
		    finally // make sure we clean up the connections
		    {
				try
				{
				    if(Out != null) Out.close();
				    if(In != null) In.close();
				    if(Socket != null) Socket.close();
				}
				catch (IOException e)
				{
				    System.out.println("IOException in finally block: " + e);
				}	    
		    }
		
		} while(timeEnd==0); // if it broke before we completed, just try again
		
		return((timeEnd-timeStart)/1000); // time in microseconds
    }
}
