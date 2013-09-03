package org.jivesoftware.smack;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

import org.jivesoftware.smack.debugger.SmackDebugger;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.parsing.ParsingExceptionCallback;


/**
 * Link-local XMPP connection according to XEP-0174 connection. Automatically
 * created by LLService and closed by inactivity.
 *
 */
public class XMPPLLConnection extends Connection // public for debugging reasons
{
    private final static Set<LLConnectionListener> linkLocalListeners =
            new CopyOnWriteArraySet<LLConnectionListener>();
    
    private final LLService service;
    private LLPresence localPresence, remotePresence;
    private boolean initiator;
    private long lastActivity = 0;
    protected XMPPLLConnection connection;
    private final Thread timeoutThread;

    private final LLConnectionConfiguration configuration;

    /**
     * The socket which is used for this connection.
     * @see XMPPConnection#socket
     */
    Socket socket;
    /**
     * @see XMPPConnection#parsingExceptionCallback 
     */
    private final ParsingExceptionCallback parsingExceptionCallback = SmackConfiguration.getDefaultParsingExceptionCallback();
    PacketWriter packetWriter;
    AbstractPacketReader packetReader;
    private boolean connected = false;

    /**
     * Hostname of the XMPP server. Usually servers use the same service name as the name
     * of the server. However, there are some servers like google where host would be
     * talk.google.com and the serviceName would be gmail.com.
     * @see ConnectionConfiguration#getServiceName()
     */
    private String serviceName;
    String connectionID = null;
    /**
     * socketClosed is used concurrent
     * by XMPPConnection, PacketReader, PacketWriter
     * @see XMPPConnection#socketClosed
     */
    private volatile boolean socketClosed = false;

    /**
     * Collection of available stream compression methods offered by the server.
     * @see XMPPConnection#compressionMethods
     */
    private Collection<String> compressionMethods;

    /**
     * Set to true by packet writer if the server acknowledged the compression
     * @see XMPPConnection#serverAckdCompression
     */
    private boolean serverAckdCompression = false;

    /**
     * @see XMPPConnection#usingTLS 
     */
    private boolean usingTLS = false;
    
    /**
     * Instantiate a new link-local connection. Use the config parameter to
     * specify if the connection is acting as server or client.
     *
     * @param config specification about how the new connection is to be set up.
     */
    XMPPLLConnection(LLService service, LLConnectionConfiguration config) {
    	super(config);
        connection = this;
        this.service = service;
        configuration = config;
        updateLastActivity();

        // A timeout thread's purpose is to close down inactive connections
        // after a certain amount of seconds (defaults to 15).
        timeoutThread = new Thread() {
            @Override
			public void run() {
                try {
                    while (connection != null) {
                        //synchronized (connection) {
                            Thread.sleep(14000);
                            long currentTime = new Date().getTime();
                            if (currentTime - lastActivity > 15000) {
                                shutdown();
                                break;
                            }
                        //}
                    }
                } catch (InterruptedException ie) {
                    shutdown();
                }
            }
        };

        timeoutThread.setName("Smack Link-local Connection Timeout (" + connection.connectionCounterValue + ")");
        timeoutThread.setDaemon(true);


        if (config.isInitiator()) {
            // we are connecting to remote host
            localPresence = config.getLocalPresence();
            remotePresence = config.getRemotePresence();
            serviceName = remotePresence.getServiceName();
            initiator = true;
        } else {
            // a remote host connected to us
            localPresence = config.getLocalPresence();
            remotePresence = null;
            serviceName = null;
            initiator = false;
            socket = config.getSocket();
        }
    }

    @Override
	public String getConnectionID() {
        if (!isConnected()) {
            return null;
        }
        return connectionID;
    }

    /**
     * Tells if this connection instance is the initiator.
     *
     * @return true if this instance is the one connecting to a remote peer.
     */
    public boolean isInitiator() {
        return initiator;
    }

    /**
     * Return the user name of the remote peer (service name).
     *
     * @return the remote hosts service name / username
     */
    @Override
	public String getUser() {
        // username is the service name of the local presence
        return localPresence.getServiceName();
    }

    /**
     * Sets the name of the service provided in the <stream:stream ...> from the remote peer.
     *
     * @param serviceName the name of the service
     */
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }


    /**
     * Set the remote presence. Used when being connected,
     * will not know the remote service name until stream is initiated.
     *
     * @param remotePresence presence information about the connecting client.
     */
    void setRemotePresence(LLPresence remotePresence) {
        this.remotePresence = remotePresence;
    }

    /**
     * Start listen for data and a stream tag.
     */
    void initListen() throws XMPPException {
        initConnection();
    }

    /**
     * Adds a listener that are notified when a new link-local connection
     * has been established.
     *
     * @param listener A class implementing the LLConnectionListener interface.
     */
    public static void addLLConnectionListener(LLConnectionListener listener) {
        linkLocalListeners.add(listener);
    }

    /**
     * Removes a listener from the new connection listener list.
     *
     * @param listener The class implementing the LLConnectionListener interface that
     * is to be removed.
     */
    public static void removeLLConnectionListener(LLConnectionListener listener) {
        linkLocalListeners.remove(listener);
    }

    /**
     * Create a socket, connect to the remote peer and initiate a XMPP stream session.
     */
    @Override
	public void connect() throws XMPPException {
        String host = remotePresence.getHost();
        int port = remotePresence.getPort();

        try {
            socket = new Socket(host, port);
        }
        catch (UnknownHostException uhe) {
            String errorMessage = "Could not connect to " + host + ":" + port + ".";
            throw new XMPPException(errorMessage, new XMPPError(
                    XMPPError.Condition.remote_server_timeout, errorMessage),
                    uhe);
        }
        catch (IOException ioe) {
            String errorMessage = "Error connecting to " + host + ":"
                    + port + ".";
            throw new XMPPException(errorMessage, new XMPPError(
                    XMPPError.Condition.remote_server_error, errorMessage), ioe);
        }
        initConnection();

        notifyLLListenersConnected();
    }


    /**
     * Handles the opening of a stream after a remote client has connected and opened a stream.
     * @throws XMPPException if service name is missing or service is unknown to the mDNS daemon.
     */
    public void streamInitiatingReceived() throws XMPPException {
        if (serviceName == null) {
            shutdown();
        } else {
            packetWriter = new PacketWriter(this);
            if (debugger != null) {
                if (debugger.getWriterListener() != null) {
                	addPacketListener(debugger.getWriterListener(), null);
                }
            }
            packetWriter.startup();
            notifyLLListenersConnected();
        }
    }

    /**
     * Notify new connection listeners that a new connection has been established.
     */
    private void notifyLLListenersConnected() {
        for (LLConnectionListener listener : linkLocalListeners) {
            listener.connectionCreated(this);
        }
    }

    /**
     * Update the timer telling when the last activity happend. Used by timeout
     * thread to tell how long the connection has been inactive.
     */
    void updateLastActivity() {
        lastActivity = new Date().getTime();
    }

    /**
     * Sends the specified packet to the remote peer.
     *
     * @param packet the packet to send
     * @see XMPPConnection#sendPacket(Packet)
     */
    @Override
    public void sendPacket(Packet packet) {
        updateLastActivity();
        // always add the from='' attribute
        packet.setFrom(getUser());

        // from XMPPConnection
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (packet == null) {
            throw new NullPointerException("Packet is null.");
        }
        packetWriter.sendPacket(packet);
    }

    /**
     * Initializes the connection by creating a packet reader and writer and opening a
     * XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     */
    private void initConnection() throws XMPPException {
        // Set the reader and writer instance variables
        initReaderAndWriter();
        timeoutThread.start();

        try {
            // Don't initialize packet writer until we know it's a valid connection
            // unless we are the initiator. If we are NOT the initializer, we instead
            // wait for a stream initiation before doing anything.
            if (isInitiator())
                packetWriter = new PacketWriter(this);

            // Initialize packet reader
            packetReader = new LLPacketReader(service, this);

            // If debugging is enabled, we should start the thread that will listen for
            // all packets and then log them.
            // XXX FIXME
            if (false) {//configuration.isDebuggerEnabled()) {
                addPacketListener(debugger.getReaderListener(), null);
            }

            // Make note of the fact that we're now connected.
            connected = true;

            // If we are the initiator start the packet writer. This will open a XMPP
            // stream to the server. If not, a packet writer will be started after
            // receiving an initial stream start tag.
            if (isInitiator())
                packetWriter.startup();
            // Start the packet reader. The startup() method will block until we
            // get an opening stream packet back from server.
            packetReader.startup();
        }
        catch (XMPPException ex) {
            // An exception occurred in setting up the connection. Make sure we shut down the
            // readers and writers and close the socket.

            if (packetWriter != null) {
                try {
                    packetWriter.shutdown();
                }
                catch (Throwable ignore) { /* ignore */ }
                packetWriter = null;
            }
            if (packetReader != null) {
                try {
                    packetReader.shutdown();
                }
                catch (Throwable ignore) { /* ignore */ }
                packetReader = null;
            }
            if (socket != null) {
                try {
                    socket.close();
                }
                catch (Exception e) { /* ignore */ }
                socket = null;
            }
            // closing reader after socket since reader.close() blocks otherwise
            if (reader != null) {
                try {
                    reader.close();
                }
                catch (Throwable ignore) { /* ignore */ }
                reader = null;
            }
            if (writer != null) {
                try {
                    writer.close();
                }
                catch (Throwable ignore) {  /* ignore */ }
                writer = null;
            }
            connected = false;

            throw ex;        // Everything stoppped. Now throw the exception.
        }
    }

    private void initReaderAndWriter() throws XMPPException {
        try {
            reader =
                    new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
        }
        catch (IOException ioe) {
            throw new XMPPException(
                    "XMPPError establishing connection with server.",
                    new XMPPError(XMPPError.Condition.remote_server_error,
                            "XMPPError establishing connection with server."),
                    ioe);
        }

        // If debugging is enabled, we open a window and write out all network traffic.
        if (false) {//configuration.isDebuggerEnabled()) {
            if (debugger == null) {
                // Detect the debugger class to use.
                String className = null;
                // Use try block since we may not have permission to get a system
                // property (for example, when an applet).
                try {
                    className = System.getProperty("smack.debuggerClass");
                }
                catch (Throwable t) {
                    // Ignore.
                }
                Class<?> debuggerClass = null;
                if (className != null) {
                    try {
                        debuggerClass = Class.forName(className);
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                if (debuggerClass == null) {
                    try {
                        debuggerClass =
                                Class.forName("org.jivesoftware.smackx.debugger.EnhancedDebugger");
                    }
                    catch (Exception ex) {
                        try {
                            debuggerClass =
                                    Class.forName("org.jivesoftware.smack.debugger.LiteDebugger");
                        }
                        catch (Exception ex2) {
                            ex2.printStackTrace();
                        }
                    }
                }
                // Create a new debugger instance. If an exception occurs then disable the debugging
                // option
                try {
                    Constructor<?> constructor = debuggerClass
                            .getConstructor(XMPPLLConnection.class, Writer.class, Reader.class);
                    debugger = (SmackDebugger) constructor.newInstance(this, writer, reader);
                    reader = debugger.getReader();
                    writer = debugger.getWriter();
                }
                catch (Exception e) {
                    e.printStackTrace();
                    DEBUG_ENABLED = false;
                }
            }
            else {
                // Obtain new reader and writer from the existing debugger
                reader = debugger.newConnectionReader(reader);
                writer = debugger.newConnectionWriter(writer);
            }
        }
    }

    protected void shutdown() {
        connection = null;

        if (packetReader != null)
            packetReader.shutdown();
        if (packetWriter != null)
            packetWriter.shutdown();

        // Wait 150 ms for processes to clean-up, then shutdown.
        try {
            Thread.sleep(150);
        }
        catch (Exception e) {
            // Ignore.
        }

        // Close down the readers and writers.
        if (reader != null) {
            try {
                reader.close();
            }
            catch (Throwable ignore) { /* ignore */ }
            reader = null;
        }
        if (writer != null) {
            try {
                writer.close();
            }
            catch (Throwable ignore) { /* ignore */ }
            writer = null;
        }

        try {
            socket.close();
        }
        catch (Exception e) {
            // Ignore.
        }
    } 

    @Override
	public void disconnect() {
        // If not connected, ignore this request.
        if (packetReader == null || packetWriter == null) {
            return;
        }

        shutdown();

        packetWriter.cleanup();
        packetWriter = null;
        packetReader.cleanup();
        packetReader = null;
    }

    /**
     * Sends out a notification that there was an error with the connection
     * and closes the connection. Also prints the stack trace of the given exception
     *
     * @param e the exception that causes the connection close event.
     * @see XMPPConnection#notifyConnectionError(Exception)
     */
    @Override
	synchronized void notifyConnectionError(Exception e) {
        // Listeners were already notified of the exception, return right here.
        if (packetReader.done && packetWriter.done) return;

        packetReader.done = true;
        packetWriter.done = true;
        // Closes the connection temporary. A reconnection is possible
        shutdown(new Presence(Presence.Type.unavailable));
        // Print the stack trace to help catch the problem
        e.printStackTrace();
        // Notify connection listeners of the error.
        for (ConnectionListener listener : getConnectionListeners()) {
            try {
                listener.connectionClosedOnError(e);
            }
            catch (Exception e2) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                e2.printStackTrace();
            }
        }
    }
    
    /**
     * Closes the connection by setting presence to unavailable then closing the stream to
     * the XMPP server. The shutdown logic will be used during a planned disconnection or when
     * dealing with an unexpected disconnection. Unlike {@link #disconnect()} the connection's
     * packet reader, packet writer, and {@link Roster} will not be removed; thus
     * connection's state is kept.
     *
     * @param unavailablePresence the presence packet to send during shutdown.
     * @see XMPPConnection#shutdown(Presence)
     */
    protected void shutdown(Presence unavailablePresence) {
        // Set presence to offline.
        if (packetWriter != null) {
                packetWriter.sendPacket(unavailablePresence);
        }

//        this.setWasAuthenticated(authenticated);
//        authenticated = false;

        if (packetReader != null) {
                packetReader.shutdown();
        }
        if (packetWriter != null) {
                packetWriter.shutdown();
        }

        // Wait 150 ms for processes to clean-up, then shutdown.
        try {
            Thread.sleep(150);
        }
        catch (Exception e) {
            // Ignore.
        }

        // Set socketClosed to true. This will cause the PacketReader
        // and PacketWriter to ignore any Exceptions that are thrown
        // because of a read/write from/to a closed stream.
        // It is *important* that this is done before socket.close()!
//        socketClosed = true;
        try {
                socket.close();
        } catch (Exception e) {
                e.printStackTrace();
        }
        // In most cases the close() should be successful, so set
        // connected to false here.
        connected = false;

        reader = null;
        writer = null;

        saslAuthentication.init();
    }
    
    @Override
    public boolean hasPacketReader() {
    	return packetReader != null;
    }

	@Override
	public boolean isConnected() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isAuthenticated() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isAnonymous() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isSecureConnection() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isUsingCompression() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void login(String username, String password, String resource)
			throws XMPPException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void loginAnonymously() throws XMPPException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Roster getRoster() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setRosterStorage(RosterStorage storage)
			throws IllegalStateException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void disconnect(Presence unavailablePresence) {
		// TODO Auto-generated method stub
		
	}

	@Override
	boolean isSocketClosed() {
		return socketClosed;
	}

	@Override
	void setConnectionID(String connectionID) {
		this.connectionID = connectionID;
	}

	/**
	 * @see XMPPConnection#getParsingExceptionCallback()
	 */
	@Override
	ParsingExceptionCallback getParsingExceptionCallback() {
		return parsingExceptionCallback;
	}

	/**
	 * @see XMPPConnection#streamCompressionDenied()
	 */
	@Override
	void streamCompressionDenied() {
        synchronized (this) {
            this.notify();
        }
	}

	/**
	 * @see XMPPConnection#proceedTLSReceived()
	 */
	@Override
	void proceedTLSReceived() throws Exception {
        SSLContext context = this.config.getCustomSSLContext();
        KeyStore ks = null;
        KeyManager[] kms = null;
        PasswordCallback pcb = null;

        if(config.getCallbackHandler() == null) {
           ks = null;
        } else if (context == null) {
            //System.out.println("Keystore type: "+configuration.getKeystoreType());
            if(config.getKeystoreType().equals("NONE")) {
                ks = null;
                pcb = null;
            }
            else if(config.getKeystoreType().equals("PKCS11")) {
                try {
                    Constructor<?> c = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
                    String pkcs11Config = "name = SmartCard\nlibrary = "+config.getPKCS11Library();
                    ByteArrayInputStream config = new ByteArrayInputStream(pkcs11Config.getBytes());
                    Provider p = (Provider)c.newInstance(config);
                    Security.addProvider(p);
                    ks = KeyStore.getInstance("PKCS11",p);
                    pcb = new PasswordCallback("PKCS11 Password: ",false);
                    this.config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(null,pcb.getPassword());
                }
                catch (Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            else if(config.getKeystoreType().equals("Apple")) {
                ks = KeyStore.getInstance("KeychainStore","Apple");
                ks.load(null,null);
                //pcb = new PasswordCallback("Apple Keychain",false);
                //pcb.setPassword(null);
            }
            else {
                ks = KeyStore.getInstance(config.getKeystoreType());
                try {
                    pcb = new PasswordCallback("Keystore Password: ",false);
                    config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(new FileInputStream(config.getKeystorePath()), pcb.getPassword());
                }
                catch(Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            try {
                if(pcb == null) {
                    kmf.init(ks,null);
                } else {
                    kmf.init(ks,pcb.getPassword());
                    pcb.clearPassword();
                }
                kms = kmf.getKeyManagers();
            } catch (NullPointerException npe) {
                kms = null;
            }
        }

        // Verify certificate presented by the server
        if (context == null) {
            context = SSLContext.getInstance("TLS");
            context.init(kms, new javax.net.ssl.TrustManager[] { new ServerTrustManager(getServiceName(), config) },
                    new java.security.SecureRandom());
        }
        Socket plain = socket;
        // Secure the plain connection
        socket = context.getSocketFactory().createSocket(plain,
                plain.getInetAddress().getHostAddress(), plain.getPort(), true);
        socket.setSoTimeout(0);
        socket.setKeepAlive(true);
        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();
        // Proceed to do the handshake
        ((SSLSocket) socket).startHandshake();
        //if (((SSLSocket) socket).getWantClientAuth()) {
        //    System.err.println("Connection wants client auth");
        //}
        //else if (((SSLSocket) socket).getNeedClientAuth()) {
        //    System.err.println("Connection needs client auth");
        //}
        //else {
        //    System.err.println("Connection does not require client auth");
       // }
        // Set that TLS was successful
        usingTLS = true;

        // Set the new  writer to use
        packetWriter.setWriter(writer);
        // Send a new opening stream to the server
        packetWriter.openStream();
	}

	/**
	 * @see XMPPConnection#openWriterStream()
	 */
	@Override
	void openWriterStream() throws IOException {
		packetWriter.openStream();
	}

	/**
	 * @see XMPPConnection#startStreamCompression()
	 */
	@Override
	void startStreamCompression() throws Exception {
        serverAckdCompression = true;
        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();

        // Set the new  writer to use
        packetWriter.setWriter(writer);
        // Send a new opening stream to the server
        packetWriter.openStream();
        // Notify that compression is being used
        synchronized (this) {
            this.notify();
        }
	}

	/**
	 * @see XMPPConnection#setAvailableCompressionMethods(java.util.Collection)
	 */
	@Override
	void setAvailableCompressionMethods(Collection<String> methods) {
		compressionMethods = methods;
	}

	/**
	 * @see XMPPConnection#startTLSReceived(boolean)
	 */
	@Override
	void startTLSReceived(boolean required) {
        if (required && config.getSecurityMode() ==
                ConnectionConfiguration.SecurityMode.disabled) {
            notifyConnectionError(new IllegalStateException(
                    "TLS required by server but not allowed by connection configuration"));
            return;
        }

        if (config.getSecurityMode() == ConnectionConfiguration.SecurityMode.disabled) {
            // Do not secure the connection using TLS since TLS was disabled
            return;
        }
        try {
            writer.write("<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>");
            writer.flush();
        }
        catch (IOException e) {
            notifyConnectionError(e);
        }
	}

}
