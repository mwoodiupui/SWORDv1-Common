/**
 * Copyright (c) 2007, Aberystwyth University
 *
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 *  - Redistributions of source code must retain the above 
 *    copyright notice, this list of conditions and the 
 *    following disclaimer.
 *  
 *  - Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *    the documentation and/or other materials provided with the 
 *    distribution.
 *    
 *  - Neither the name of the Centre for Advanced Software and 
 *    Intelligent Systems (CASIS) nor the names of its 
 *    contributors may be used to endorse or promote products derived 
 *    from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

package org.purl.sword.server;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.purl.sword.atom.Author;
import org.purl.sword.atom.Content;
import org.purl.sword.atom.Contributor;
import org.purl.sword.atom.Generator;
import org.purl.sword.atom.InvalidMediaTypeException;
import org.purl.sword.atom.Link;
import org.purl.sword.atom.Source;
import org.purl.sword.atom.Summary;
import org.purl.sword.atom.Title;
import org.purl.sword.base.Collection;
import org.purl.sword.base.Deposit;
import org.purl.sword.base.DepositResponse;
import org.purl.sword.base.ErrorCodes;
import org.purl.sword.base.SWORDAuthenticationException;
import org.purl.sword.base.SWORDEntry;
import org.purl.sword.base.SWORDException;
import org.purl.sword.base.Service;
import org.purl.sword.base.ServiceDocument;
import org.purl.sword.base.ServiceDocumentRequest;
import org.purl.sword.base.ServiceLevel;
import org.purl.sword.base.Workspace;

/**
 * A 'dummy server' which acts as dumb repository which implements the
 * SWORD ServerInterface. It accepts any type of deposit, and tries to
 * return appropriate responses.
 * 
 * It supports authentication: if the username and password match
 * (case sensitive) it authenticates the user, if not, the authentication 
 * fails.
 * 
 * @author Stuart Lewis
 */
public class DummyServer implements SWORDServer {

	/** A counter to count submissions, so the response to a deposito can increment */
	private static int counter = 0;

	/**
	 * Provides a dumb but plausible service document - it contains
	 * an anonymous workspace and collection, and one personalised
	 * for the onBehalfOf user.
	 * 
	 * @param onBehalfOf The user that the client is acting on behalf of
	 * @throws SWORDAuthenticationException 
	 */
	public ServiceDocument doServiceDocument(ServiceDocumentRequest sdr) throws SWORDAuthenticationException {
		// Authenticate the user
		String username = sdr.getUsername();
		String password = sdr.getPassword();
		if ((username != null) && (password != null) && 
			(((username.equals("")) && (password.equals(""))) || 
		     (!username.equalsIgnoreCase(password))) ) {
				// User not authenticated
				throw new SWORDAuthenticationException("Bad credentials");
		}
		
		// Create and return a dummy ServiceDocument
		ServiceDocument document = new ServiceDocument();
		Service service = new Service(ServiceLevel.ZERO, true, true);
	    document.setService(service);
	    
	    Workspace workspace = new Workspace();
	    workspace.setTitle("Anonymous submitters workspace");
	    Collection collection = new Collection(); 
	    collection.setTitle("Anonymous submitters collection");
	    collection.setLocation("http://sword.aber.ac.uk/sword/deposit?user=anon");
	    workspace.addCollection(collection);
	    collection = new Collection(); 
	    collection.setTitle("Anonymous submitters other collection");
	    collection.setLocation("http://sword.aber.ac.uk/sword/deposit?user=anonymous");
	    workspace.addCollection(collection);
	    service.addWorkspace(workspace);
	     
	    if (sdr.getUsername() != null) {
	    	workspace = new Workspace();
		    workspace.setTitle("Authenticated workspace for " + username);
		    collection = new Collection(); 
		    collection.setTitle("Authenticated collection for " + username);
		    collection.setLocation("http://sword.aber.ac.uk/sword/deposit?user=" + username);
		    workspace.addCollection(collection);
		    collection = new Collection(); 
		    collection.setTitle("Second authenticated collection for " + username);
		    collection.setLocation("http://sword.aber.ac.uk/sword/deposit?user=" + username + "-2");
		    workspace.addCollection(collection);
		    service.addWorkspace(workspace);
	    }
	    
	    String onBehalfOf = sdr.getOnBehalfOf();
	    if ((onBehalfOf != null) && (!onBehalfOf.equals(""))) {
		    workspace = new Workspace();
		    workspace.setTitle("Personal workspace for " + onBehalfOf);
		    collection = new Collection(); 
		    collection.setTitle("Personal collection for " + onBehalfOf);
		    collection.setLocation("http://sword.aber.ac.uk/sword/deposit?user=" + onBehalfOf);
		    collection.addAccepts("application/zip");
		    collection.addAccepts("application/xml");
		    collection.setAbstract("An abstract goes in here");
		    collection.setCollectionPolicy("A collection policy");
		    collection.setMediation(true);
		    collection.setTreatment("treatment in here too");
		    workspace.addCollection(collection);
		    service.addWorkspace(workspace);
	    }
	    
	    return document;
	}

	public DepositResponse doDeposit(Deposit deposit) throws SWORDAuthenticationException, SWORDException {
		// Authenticate the user
		String username = deposit.getUsername();
		String password = deposit.getPassword();
		if ((username != null) && (password != null) && 
			(((username.equals("")) && (password.equals(""))) || 
			 (!username.equalsIgnoreCase(password))) ) {
			// User not authenticated
			throw new SWORDAuthenticationException("Bad credentials");
		}
		
		// Get the filenames
		StringBuffer filenames = new StringBuffer("Deposit file contained: ");
		if (deposit.getFilename() != null) {
			filenames.append("(filename = " + deposit.getFilename() + ") ");
		}
		if (deposit.getSlug() != null) {
			filenames.append("(slug = " + deposit.getSlug() + ") ");
		}
		try {
			ZipInputStream zip = new ZipInputStream(deposit.getFile());
			ZipEntry ze;
			while ((ze = zip.getNextEntry()) != null) {
				filenames.append(" " + ze.toString());
			}
		} catch (IOException ioe) {
			throw new SWORDException("Failed to open deposited zip file", null, ErrorCodes.ERROR_CONTENT);
		}
		
		// Handle the deposit
		if (!deposit.isNoOp()) {
			counter++;
		}
		DepositResponse dr = new DepositResponse(Deposit.ACCEPTED);
		SWORDEntry se = new SWORDEntry();
		
		Title t = new Title();
		t.setContent("DummyServer Deposit: #" + counter);
		se.setTitle(t);
		
		se.addCategory("Category");
		
		if (deposit.getSlug() != null) {
			se.setId(deposit.getSlug() + " - ID: " + counter);
		} else {
			se.setId("ID: " + counter);
		}
		 
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		TimeZone utc = TimeZone.getTimeZone("UTC");
		sdf.setTimeZone (utc);
		String milliFormat = sdf.format(new Date());
		se.setUpdated(milliFormat);
			
	    Summary s = new Summary();
		s.setContent(filenames.toString());
		se.setSummary(s);
		Author a = new Author();
		if (username != null) {
			a.setName(username);
		} else {
			a.setName("unknown");
		}
		se.addAuthors(a);
		
		Link em = new Link();
		em.setRel("edit-media");
		em.setHref("http://www.myrepository.ac.uk/sdl/workflow/my deposit");
		se.addLink(em);
		
		Link e = new Link();
		e.setRel("edit");
		e.setHref("http://www.myrepository.ac.uk/sdl/workflow/my deposit.atom");
		se.addLink(e);
		
		if (deposit.getOnBehalfOf() != null) {
			Contributor c = new Contributor();
			c.setName(deposit.getOnBehalfOf());
			c.setEmail(deposit.getOnBehalfOf() + "@myrepository.ac.uk");
			se.addContributor(c);
		}
		
		Source source = new Source();
		Generator generator = new Generator();
		generator.setContent("org.purl.sword.server.DummyServer");
		source.setGenerator(generator);
		se.setSource(source);
		
		Content content = new Content();
		try {
			content.setType("application/zip");
		} catch (InvalidMediaTypeException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		content.setSource("http://www.myrepository.ac.uk/sdl/uploads/upload-" + counter + ".zip");
		se.setContent(content);
		
		se.setTreatment("Short back and sides");
		
		if (deposit.isVerbose()) {
			se.setVerboseDescription("I've done a lot of hard work to get this far!");
		}
		
		se.setNoOp(deposit.isNoOp());
		
		se.setFormatNamespace("http://www.standards-body.com/standardXYZ/v1/");
		
		dr.setEntry(se);
		
		return dr;
	}
}