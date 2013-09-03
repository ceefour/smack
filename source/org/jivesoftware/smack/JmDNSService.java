package org.jivesoftware.smack;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Hashtable;

import javax.annotation.PreDestroy;
import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
//import javax.jmdns.impl.JmDNSImpl;
//import javax.jmdns.impl.DNSRecord;
//import javax.jmdns.impl.DNSListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jivesoftware.smack.util.Tuple;

/**
 * Implements a LLService using JmDNS.
 *
 * @author Jonas Ådahl
 */
public class JmDNSService extends LLService implements Closeable {
	private static final Log log = LogFactory.getLog(JmDNSService.class);
    static JmDNS jmdns = null;
    static JmDNSPresenceDiscoverer presenceDiscoverer = null;
    private ServiceInfo serviceInfo;
    static final String SERVICE_TYPE = "_presence._tcp.local.";

    private JmDNSService(LLPresence presence, LLPresenceDiscoverer presenceDiscoverer) {
        super(presence, presenceDiscoverer);
    }

    /**
     * Instantiate a new JmDNSService and start to listen for connections.
     *
     * @param presence the mDNS presence information that should be used.
     */
    public static LLService create(LLPresence presence) throws XMPPException {
        // Start the JmDNS daemon.
        initJmDNS();

        // Start the presence discoverer
        JmDNSPresenceDiscoverer presenceDiscoverer = new JmDNSPresenceDiscoverer();

        // Start the presence service
        JmDNSService service = new JmDNSService(presence, presenceDiscoverer);

        // Initiate the mDNS XMPP Service 
        //service.init();

        return service;
    }

    @Override @PreDestroy
    public void close() {
        super.close();
        try {
			jmdns.close();
		} catch (IOException e) {
			log.warn("Cannot close JmDNS: " + e, e);
		}
    }

    /**
     * Start the JmDNS daemon.
     */
    private static void initJmDNS() throws XMPPException {
        try {
            if (jmdns == null) {
                jmdns = JmDNS.create();
            }
        }
        catch (IOException ioe) {
            throw new XMPPException(ioe);
        }
    }

    @Override
	protected void updateText() {
        Hashtable<String,String> ht = new Hashtable<String,String>();
        
        for (Tuple<String,String> t : presence.toList()) {
            if (t.a != null && t.b != null) {
                ht.put(t.a, t.b);
            }
        }

        serviceInfo.setText(ht);
    }

    /**
     * Register the DNS-SD service with the daemon.
     */
    @Override
	protected void registerService() throws XMPPException {
        Hashtable<String,String> ht = new Hashtable<String,String>();
        
        for (Tuple<String,String> t : presence.toList()) {
            if (t.a != null && t.b != null)
                ht.put(t.a, t.b);
        }
        serviceInfo = ServiceInfo.create(SERVICE_TYPE,
                presence.getServiceName(), presence.getPort(), 0, 0, new HashMap<String, String>());//ht);
        try {
        	log.info("Registering XMPP Presence '" + serviceInfo.getType() + "' service '" + serviceInfo.getName() + "' at port " + serviceInfo.getPort() +
        			" using " + ht);
            jmdns.registerService(serviceInfo);
        }
        catch (IOException ioe) {
            throw new XMPPException(ioe);
        }
    }

    /**
     * Reregister the DNS-SD service with the daemon.
     */
    @Override
	protected void reannounceService() throws XMPPException {
        try {
        	// FIXME: reannounceService() doesn't exist now with jmdns-kohsuke 3.4.0?
        	jmdns.registerService(serviceInfo);
//            jmdns.reannounceService(serviceInfo);
        }
        catch (IOException ioe) {
            throw new XMPPException("Exception occured when reannouncing mDNS presence.", ioe);
        }
    }

    /**
     * Unregister the DNS-SD service, making the client unavailable.
     */
    @Override
	public void makeUnavailable() {
        jmdns.unregisterService(serviceInfo);
        serviceInfo = null;
    }
}
