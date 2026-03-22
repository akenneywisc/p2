package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.IPv4;
import java.util.Map;

import net.floodlightcontroller.packet.Ethernet;
import java.util.concurrent.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
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


	public void startRIP(){

		for (Iface iface : this.interfaces.values()) {
			int ip = iface.getIpAddress();
			int mask = iface.getSubnetMask();
			int network = ip & mask;
			this.routeTable.insert(network, 0, mask, iface);
		}

		
		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(() -> {
			System.out.println("Running RIP update...");
			System.out.println(this.routeTable);
		}, 0, 10, TimeUnit.SECONDS);
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
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
