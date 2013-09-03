package org.jivesoftware.smack.test;

//import javax.jmdns.impl.SocketListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jivesoftware.smack.JmDNSService;
import org.jivesoftware.smack.LLChat;
import org.jivesoftware.smack.LLChatListener;
import org.jivesoftware.smack.LLMessageListener;
import org.jivesoftware.smack.LLPresence;
import org.jivesoftware.smack.LLService;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smackx.LLServiceDiscoveryManager;
import org.jivesoftware.smackx.packet.DiscoverInfo;

public class TestMDNS {
    LLService service;
    public static void main(String[] argv) {
        Handler ch = new ConsoleHandler();
        //System.out.println(ConsoleHandler.class.getName());
        Logger.getLogger("").addHandler(ch);
        //Logger.getLogger("javax.jmdns.impl.SocketListener").setLevel(Level.FINEST);
        TestMDNS test = new TestMDNS();
        test.run();
    }

    public void run() {
    	LLServiceDiscoveryManager.registerLLServiceListener();
        try {
            // Initiate stdin buffer for reading commands (the fancy UI)
            BufferedReader stdIn = new BufferedReader(
                    new InputStreamReader(System.in));

            // Create some kind of user name
            String name = "smack-mdns@localhost";
            try {
                Matcher matcher = Pattern.compile("([^.]+).*").matcher(java.net.InetAddress.getLocalHost().getHostName());
                matcher.matches();
                final String shortHostName = matcher.group(1);
				name = System.getenv("USERNAME") + "@" + shortHostName;
            } catch (Exception e) {}

            System.out.println("Link-local presence name set to '" + name + "'");
            // Create a basic presence (only set name, and status to available)
            LLPresence presence = new LLPresence(name);

            System.out.println("Initiating Link-local service...");
            // Create a XMPP Link-local service.
            service = JmDNSService.create(presence);

            // Adding presence listener.
            service.addPresenceListener(new MDNSListener());

            System.out.println("Preparing link-local service discovery...");
            // As we want to play with service discovery, initiate the wrapper
            LLServiceDiscoveryManager disco = LLServiceDiscoveryManager.getInstanceFor(service);

            if (disco == null) {
                System.err.println("Failed to initiated Service Discovery Manager.");
                System.exit(1);
            }

            System.out.println("Adding three features to service discovery manager...");
            disco.addFeature("http://www.jabber.org/extensions/lalal");
            disco.addFeature("http://www.jabber.org/extenions/thetetteet");
            disco.addFeature("urn:xmpp:hejhoppextension");

            // Start listen for Link-local chats
            service.addLLChatListener(new MyChatListener());

            // Add hook for doing a clean shut down
            Runtime.getRuntime().addShutdownHook(new CloseDownService(service));

            // Initiate Link-local message session
            service.init();

            // Implement a user friendly interface.
            String line;
            boolean done = false;

            System.out.println("Welcome to the Smack Link-local sample client interface!");
            System.out.println("========================================================");
            while (!done) {
                try {
                    System.out.print("> ");
                    line = stdIn.readLine();
                    if ("quit".equals(line))
                        done = true;
                    else if ("spam".equals(line)) {
                        service.spam();
                        // FIXME: not implemented by 3.4.0
//                        ServiceDiscoveryManager.spam();
                    }
                    else if ("msg".equals(line)) {
                        System.out.print("Enter user: ");
                        String user = stdIn.readLine();
                        System.out.print("Enter message: ");
                        String message = stdIn.readLine();
                        LLChat chat = service.getChat(user);
                        chat.sendMessage(message);
                        System.out.println("Message sent.");
                    }
                    else if ("addfeature".equals(line)) {
                        System.out.print("Enter new feature: ");
                        String feature = stdIn.readLine();
                        disco.addFeature(feature);
                    }
                    else if ("disco".equals(line)) {
                        System.out.print("Enter user: ");
                        String user = stdIn.readLine();
                        DiscoverInfo info = disco.discoverInfo(user);
                        System.out.println(" # Discovered: " + info.toXML());
                    }
                    else if ("status".equals(line)) {
                        System.out.print("Enter new status: ");
                        String status = stdIn.readLine();
                        try {
                            presence.setStatus(LLPresence.Mode.valueOf(status));
                            service.updatePresence(presence);
                        }
                        catch (IllegalArgumentException iae) {
                            System.err.println("Illegal status: " + status);
                        }
                    }
                }
                catch (XMPPException xe) {
                    System.out.println("Cought XMPPException: " + xe);
                    xe.printStackTrace();
                    //done = true;
                }
                catch (IOException ioe) {
                    System.out.println("Cought IOException: " + ioe);
                    ioe.printStackTrace();
                    done = true;
                }
            }
            System.exit(0);
        } catch (XMPPException xe) {
            System.err.println(xe);
        }
    }

    private class CloseDownService extends Thread {
        LLService service;
        
        public CloseDownService(LLService service) {
            this.service = service;
        }

        @Override
		public void run () {
            System.out.println("### Unregistering service....");
            //service.makeUnavailable();
            System.out.println("### Done, now closing daemon...");

            try { Thread.sleep(1000); } catch (Exception e) { }
            service.close();
            System.out.println("### Done.");
            try { Thread.sleep(2000); } catch (Exception e) { }
            Thread.currentThread().getThreadGroup().list();
        }
    }

    private class MyChatListener implements LLChatListener {
        public MyChatListener() {}

        @Override
		public void newChat(LLChat chat) {
            System.out.println("Discovered new chat being created.");
            chat.addMessageListener(new MyMessageListener(chat));
        }
    }

    private class MyMessageListener implements LLMessageListener {
        LLChat chat;

        MyMessageListener(LLChat chat) {
            this.chat = chat;
        }

        @Override
		public void processMessage(LLChat chat, Message message) {
            try {
                if (message.getBody().equals("ping")) {
                    chat.sendMessage("pong");
                    System.out.println("### received a ping, replied with pong.");
                }
                else if (message.getBody().equals("spam")) {
                    service.spam();
                }
                else {
                    System.out.println("### <" + chat.getServiceName() +
                            "> " + message.getBody());
                }
            }
            catch (XMPPException xe) {
                System.out.println("Cought exception in message listener: " + xe);
                xe.printStackTrace();
            }
        }
    }
}
