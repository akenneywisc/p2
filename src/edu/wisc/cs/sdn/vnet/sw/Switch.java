package edu.wisc.cs.sdn.vnet.sw;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.HashMap;
import java.util.Map;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {
	private static final long TIMEOUT_MS = 15_000;

	private static class MacEntry {
		Iface iface;
		long timestamp;
	}

	private final Map<MACAddress, MacEntry> macTable = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile) {
		super(host, logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		/* TODO: Handle packets (finished) */
		MACAddress src = etherPacket.getSourceMAC();
		MACAddress dst = etherPacket.getDestinationMAC();
		long time = System.currentTimeMillis();

		// Update source MAC
		MacEntry entry = new MacEntry();
		entry.iface = inIface;
		entry.timestamp = time;
		macTable.put(src, entry);

		// Forward
		MacEntry dstEntry = macTable.get(dst);
		if (dstEntry != null && (time - dstEntry.timestamp) < TIMEOUT_MS) {
			if (dstEntry.iface != inIface) sendPacket(etherPacket, dstEntry.iface);
		} else {
			// Flood for unknown or expired
			for (Iface iface : this.interfaces.values()) {
				if (iface != inIface) sendPacket(etherPacket, iface);
			}
		}
	}
}
