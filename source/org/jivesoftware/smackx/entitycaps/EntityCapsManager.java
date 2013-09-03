package org.jivesoftware.smackx.entitycaps;

public interface EntityCapsManager {

	public static final String NAMESPACE = "http://jabber.org/protocol/caps";
	public static final String ELEMENT = "c";
	static final String ENTITY_NODE = "http://www.igniterealtime.org/projects/smack";

	public abstract void enableEntityCaps();

	public abstract void disableEntityCaps();

	public abstract boolean entityCapsEnabled();

	/**
	 * Remove a record telling what entity caps node a user has.
	 * 
	 * @param user
	 *            the user (Full JID)
	 */
	public abstract void removeUserCapsNode(String user);

	/**
	 * Get our own caps version. The version depends on the enabled features. A
	 * caps version looks like '66/0NaeaBKkwk85efJTGmU47vXI='
	 * 
	 * @return our own caps version
	 */
	public abstract String getCapsVersion();

	/**
	 * Returns the local entity's NodeVer (e.g.
	 * "http://www.igniterealtime.org/projects/smack/#66/0NaeaBKkwk85efJTGmU47vXI=
	 * )
	 * 
	 * @return
	 */
	public abstract String getLocalNodeVer();

	/**
	 * Returns true if Entity Caps are supported by a given JID
	 * 
	 * @param jid
	 * @return
	 */
	public abstract boolean areEntityCapsSupported(String jid);

	/**
	 * Returns true if Entity Caps are supported by the local service/server
	 * 
	 * @return
	 */
	public abstract boolean areEntityCapsSupportedByServer();

	/**
	 * Updates the local user Entity Caps information with the data provided
	 * 
	 * If we are connected and there was already a presence send, another
	 * presence is send to inform others about your new Entity Caps node string.
	 * 
	 * @param discoverInfo
	 *            the local users discover info (mostly the service discovery
	 *            features)
	 * @param identityType
	 *            the local users identity type
	 * @param identityName
	 *            the local users identity name
	 * @param extendedInfo
	 *            the local users extended info
	 */
	public abstract void updateLocalEntityCaps();

}