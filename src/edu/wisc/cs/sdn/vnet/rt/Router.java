package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** RIP metrics keyed by "dstIp/maskIp" */
	private Map<String, Integer> ripMetrics     = new HashMap<>();
	/** RIP last-updated timestamps keyed by "dstIp/maskIp" */
	private Map<String, Long>    ripTimestamps  = new HashMap<>();

	private static final int  RIP_MULTICAST_IP = IPv4.toIPv4Address("224.0.0.9");
	private static final MACAddress RIP_BROADCAST_MAC =
			MACAddress.valueOf("FF:FF:FF:FF:FF:FF");
	private static final int  RIP_INFINITY      = 16;
	private static final long RIP_TIMEOUT_MS    = 30000; // 30 seconds
	private static final int  RIP_UPDATE_SECS   = 10;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }


	private static String ripKey(int dstIp, int maskIp)
	{ return dstIp + "/" + maskIp; }

	public void startRIP(){

		for (Iface iface : this.interfaces.values()) {
			int network = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insert(network, 0, iface.getSubnetMask(), iface);
			String key = ripKey(network, iface.getSubnetMask());
			ripMetrics.put(key, 1);
			// directly-connected routes never time out; no timestamp needed
		}

		// Send an initial RIP request out every interface
		for (Iface iface : this.interfaces.values()) {
			sendRipRequest(iface);
		}

		
		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(() -> {
			removeTimedOutEntries();
			sendUnsolicitedRipResponse();
		}, RIP_UPDATE_SECS, RIP_UPDATE_SECS, TimeUnit.SECONDS);
	}

	private void removeTimedOutEntries()
	{
		long now = System.currentTimeMillis();
		List<RouteEntry> toRemove = new LinkedList<>();
		for (RouteEntry entry : this.routeTable.getEntries()) {
			// Skip directly-connected routes (gateway == 0)
			if (entry.getGatewayAddress() == 0) { continue; }
			String key = ripKey(entry.getDestinationAddress(), entry.getMaskAddress());
			Long ts = ripTimestamps.get(key);
			if (ts != null && now - ts > RIP_TIMEOUT_MS) {
				toRemove.add(entry);
			}
		}
		for (RouteEntry entry : toRemove) {
			String key = ripKey(entry.getDestinationAddress(), entry.getMaskAddress());
			this.routeTable.remove(entry.getDestinationAddress(), entry.getMaskAddress());
			ripMetrics.remove(key);
			ripTimestamps.remove(key);
		}
	}

	private void sendRipPacket(RIPv2 rip, Iface outIface, int destIp, MACAddress destMac)
	{
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(rip);

		IPv4 ip = new IPv4();
		ip.setSourceAddress(outIface.getIpAddress());
		ip.setDestinationAddress(destIp);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setTtl((byte) 64);
		ip.setPayload(udp);

		Ethernet eth = new Ethernet();
		eth.setEtherType(Ethernet.TYPE_IPv4);
		eth.setSourceMACAddress(outIface.getMacAddress().toBytes());
		eth.setDestinationMACAddress(destMac.toBytes());
		eth.setPayload(ip);

		this.sendPacket(eth, outIface);
	}

	private void sendRipRequest(Iface iface)
	{
		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_REQUEST);
		sendRipPacket(rip, iface, RIP_MULTICAST_IP, RIP_BROADCAST_MAC);
	}

	private void sendUnsolicitedRipResponse()
	{
		for (Iface iface : this.interfaces.values()) {
			sendRipResponse(iface, RIP_MULTICAST_IP, RIP_BROADCAST_MAC);
		}
	}

	private void sendRipResponse(Iface outIface, int destIp, MACAddress destMac)
	{
		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		for (RouteEntry entry : this.routeTable.getEntries()) {
			String key = ripKey(entry.getDestinationAddress(), entry.getMaskAddress());
			int metric = ripMetrics.getOrDefault(key, RIP_INFINITY);
			RIPv2Entry ripEntry = new RIPv2Entry(
					entry.getDestinationAddress(),
					entry.getMaskAddress(),
					metric);
			rip.addEntry(ripEntry);
		}
		sendRipPacket(rip, outIface, destIp, destMac);
	}

	private void handleRipPacket(Ethernet etherPacket, IPv4 ipPacket, Iface inIface)
	{
		UDP udp = (UDP) ipPacket.getPayload();
		if (!(udp.getPayload() instanceof RIPv2)) { return; }
		RIPv2 rip = (RIPv2) udp.getPayload();

		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			// Unicast response back to the requesting router
			int srcIp = ipPacket.getSourceAddress();
			MACAddress srcMac = MACAddress.valueOf(etherPacket.getSourceMACAddress());
			sendRipResponse(inIface, srcIp, srcMac);

		} else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			int srcIp = ipPacket.getSourceAddress();

			for (RIPv2Entry ripEntry : rip.getEntries()) {
				int network   = ripEntry.getAddress();
				int mask      = ripEntry.getSubnetMask();
				int newMetric = ripEntry.getMetric() + 1;

				if (newMetric >= RIP_INFINITY) { continue; }

				String key = ripKey(network, mask);
				Integer existingMetric = ripMetrics.get(key);

				if (existingMetric == null) {
					// New destination
					this.routeTable.insert(network, srcIp, mask, inIface);
					ripMetrics.put(key, newMetric);
					ripTimestamps.put(key, System.currentTimeMillis());
				} else if (newMetric < existingMetric) {
					this.routeTable.update(network, mask, srcIp, inIface);
					ripMetrics.put(key, newMetric);
					ripTimestamps.put(key, System.currentTimeMillis());
				} else {
					// Same or worse metric — but if it's the same next-hop refresh
					RouteEntry existing = null;
					for (RouteEntry e : this.routeTable.getEntries()) {
						if (e.getDestinationAddress() == network
								&& e.getMaskAddress() == mask) {
							existing = e;
							break;
						}
					}
					if (existing != null && existing.getGatewayAddress() == srcIp) {
						ripTimestamps.put(key, System.currentTimeMillis());
					}
				}
			}
		}
	}
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		
		/********************************************************************/
		short type = etherPacket.getEtherType();
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) return;
		IPv4 pkt = (IPv4) etherPacket.getPayload();

		int destinationAddress = pkt.getDestinationAddress();
		int headerLengthBytes = 4 * pkt.getHeaderLength();
		
		short checksum = pkt.getChecksum();
		pkt.setChecksum((short)0);

		pkt.serialize();

		short computedChecksum = pkt.getChecksum();
		if (computedChecksum != checksum) return;

		// Intercept RIP packets (UDP port 520)
		if (pkt.getProtocol() == IPv4.PROTOCOL_UDP) {
			UDP udp = (UDP) pkt.getPayload();
			if (udp.getDestinationPort() == UDP.RIP_PORT) {
				handleRipPacket(etherPacket, pkt, inIface);
				return;
			}
		}

		byte ttl = pkt.getTtl();
		ttl--;
		pkt.setTtl(ttl);
		pkt.resetChecksum();
		pkt.serialize();
		if ((ttl & 0xFF)==0) return;
		Map<String,Iface> interfaces = this.interfaces;


		for (Iface iface : this.interfaces.values()) {
			if (pkt.getDestinationAddress() == iface.getIpAddress()) return;
		}

		RouteEntry match = this.routeTable.lookup(destinationAddress);
		if (match == null) return;

		if (match.getInterface() == inIface)
		{ return; }

		int nextHop = match.getGatewayAddress();
		if (nextHop == 0) nextHop = destinationAddress;

		ArpEntry arp = this.arpCache.lookup(nextHop);
		if (arp == null) return;

		Iface outIface = match.getInterface();

		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(arp.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
		
	}
}
