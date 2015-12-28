#include <map>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <tuple>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>				//_getch()

#include "WinDivert-1.1.6-MSVC/include/windivert.h"
#include "ipredir.h"

//quick way to link with WinDivert.lib without changing project settings
#pragma comment(lib, "WinDivert-1.1.6-MSVC/x86/WinDivert")

const int VERSION_MAJOR = 1;
const int VERSION_MINOR = 0;
const int VERSION_PATCH = 0;
const std::string VERSION_STR = "v" + std::to_string(VERSION_MAJOR) + "." + std::to_string(VERSION_MINOR) + "." + std::to_string(VERSION_PATCH);

//lol global variables!!!
ipmap_t ipmap;	//oldip->newip mapping
int dbg = 0;	//debug flag

int main(int argc, char* argv[]) {
	if (argc == 1) {
		usage(argv[0]);
		return 0;
	}

	//list of ips which will be monitored by WinDivert (outbound and inbound)
	std::vector<std::string> ipsout, ipsin;

	//put args in a string vector for easier handling
	std::vector<std::string> args = std::vector<std::string>(argv, argv+argc);

	//parse args, get ip map and lists of ips. returns debug mode
	dbg = parseArgs(args, ipmap, ipsout, ipsin);

	//write filter string using ip lists
	std::string filter = makeFilter(ipsout, ipsin);

	if (dbg) std::cout << "Filter string: " << std::endl << filter << std::endl;

	//begin WinDivert filter
	HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "Unable to open filter: #" << GetLastError() << std::endl;
		return 1;
	}

	//increase packet queue+timeout
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192)) {
		std::cout << "Unable to set queue length: #" << GetLastError() << std::endl;
		return 1;
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048)) {
		std::cout << "Unable to set queue timeout: #" << GetLastError() << std::endl;
		return 1;
	}

	//start another thread to monitor packets so that the main thread can wait for keypress
	HANDLE thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)redirThread, (LPVOID)handle, 0, NULL);
	if (thread == NULL) {
		std::cout << "Unable to start thread: #" << GetLastError() << std::endl;
		return 1;
	}

	//wait for keypress
	std::cout << "Redirecting...press any key to stop" << std::endl;
	_getch();

	//exit nicely
	std::cout << "Closing filter..." << std::endl;
	if (!WinDivertClose(handle)) {
		std::cout << "Unable to close filter: #" << GetLastError() << std::endl;
		return 1;
	}

	WaitForSingleObject(thread, INFINITE);

	return 0;
}

//main worker thread. receives captured packets, possibly modifies, and reinjects them
DWORD redirThread(LPVOID arg) {
	HANDLE handle = (HANDLE)arg;

	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;

	UINT32 from, to;

	PWINDIVERT_TCPHDR ptcphdr;
	PWINDIVERT_UDPHDR pudphdr;
	PWINDIVERT_IPHDR piphdr;

	natmap_t natmap;

	// Main loop:
	while (1)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			//if main thread closed us down, exit nicely
			if (GetLastError() == ERROR_INVALID_HANDLE || GetLastError() == ERROR_OPERATION_ABORTED)
				return 0;

			std::cout << "Failed to read packet: #" << GetLastError() << std::endl;
			continue;
		}

		//get pointers to IP and TCP/UDP headers
		WinDivertHelperParsePacket(packet, packet_len, &piphdr, NULL, NULL, NULL, &ptcphdr, &pudphdr, NULL, NULL);

		//outbound packet, change destination address and save nat entry
		if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND) {
			//generate nat tuple
			nattuple_t tup = {
				piphdr->Protocol,
				piphdr->SrcAddr,
				piphdr->DstAddr,
				ptcphdr ? ptcphdr->SrcPort : (pudphdr ? pudphdr->SrcPort : 0),
				ptcphdr ? ptcphdr->DstPort : (pudphdr ? pudphdr->DstPort : 0),
			};

			if (dbg) std::cout << "Tx:  " << DisplayTuple(tup) << "->";

			//grab destination ip from header
			from = piphdr->DstAddr;

			//look it up in redirect map
			ipmap_t::iterator iter = ipmap.find(from);
			//if not found, inject unmodified packet (shouldn't happen for outgoing packets since
			//WinDivert only captures ones that we should be redirecting, but meh)
			if (iter == ipmap.end()) {
				if (dbg) std::cout << "X" << std::endl;
				goto outputpacket;	//goto is best way to "break" nested ifs
			}
			to = iter->second;

			if (dbg) std::cout << DottedIPv4(to) << std::endl;

			//replace with new destination ip
			piphdr->DstAddr = to;
			//modify nat tuple also
			tup.remoteip = to;

			//insert nat tuple into nat map
			natmap[tup] = from;	//lookup will give us original ip
			if (dbg) std::cout << "NAT: " << DisplayTuple(tup) << "->" << DottedIPv4(from) << std::endl;
		}

		//inbound packet, get nat tuple and look it up
		else {
			//generate nat tuple
			nattuple_t tup = {
				piphdr->Protocol,
				piphdr->DstAddr,
				piphdr->SrcAddr,
				ptcphdr ? ptcphdr->DstPort : (pudphdr ? pudphdr->DstPort : 0),
				ptcphdr ? ptcphdr->SrcPort : (pudphdr ? pudphdr->SrcPort : 0),
			};

			if (dbg) std::cout << "Rx:  " << DisplayTuple(tup) << "->";

			//look up tuple in nat map
			natmap_t::iterator iter = natmap.find(tup);
			//if nat entry not found, inject unmodified packet (would happen if directly connecting
			//to a server which happens to be a redirect destination)
			if (iter == natmap.end()) {
				if (dbg) std::cout << "X" << std::endl;
				goto outputpacket;	//goto is best way to "break" nested ifs
			}
			to = iter->second;

			if (dbg) std::cout << DottedIPv4(to) << std::endl;

			//replace with original remote ip
			piphdr->SrcAddr = to;
		}

		//jumped to if packet is unmodified
		outputpacket:

		//recalculate checksums
		WinDivertHelperCalcChecksums(packet, packet_len, 0);

		//re-inject the packet
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL)) {
			std::cout << "Failed to re-inject packet: #" << GetLastError() << std::endl;
		}
	}
}

//given outbound/inbound lists of ips, make a WinDivert filter
std::string makeFilter(std::vector<std::string> ipsout, std::vector<std::string> ipsin) {
	std::vector<std::string>::iterator iter;

	//"(outbound and (ip.SrcAddr==w.x.y.z or ip.SrcAddr==t.u.v.w or false)) or (inbound and (ip.SrcAddr==a.b.c.d or ip.SrcAddr==e.f.g.h or false))"

	std::string filter = "(outbound and (";

	for (iter = ipsout.begin(); iter != ipsout.end(); ++iter) {
		filter += ("ip.DstAddr == " + *iter + " or ");
	}

	filter += "false)) or (inbound and (";

	for (iter = ipsin.begin(); iter != ipsin.end(); ++iter) {
		filter += ("ip.SrcAddr == " + *iter + " or ");
	}

	filter += "false))";

	return filter;
}

//parse argument string and return various info
int parseArgs(std::vector<std::string> args, ipmap_t& ipmap, std::vector<std::string>& ipsout, std::vector<std::string>& ipsin) {
	UINT32 to, from;
	std::string strto, strfrom;
	std::string::size_type eq, comma;
	int dbg = 0;

	std::vector<std::string>::iterator iter;
	for (iter = args.begin(); iter != args.end(); ++iter) {
		std::string arg = *iter;

		//handle simple debug flag
		if (arg == "-d") {
			dbg = 1;
			continue;
		}

		eq = arg.find('=');
		//skip if no equals
		if (eq == std::string::npos)
			continue;

		//store 'to' ip
		strto = arg.substr(eq+1);
		if (!WinDivertHelperParseIPv4Address(strto.c_str(), &to)) {
			std::cout << "Unable to parse ip " << strto << ": #" << GetLastError() << std::endl;
			continue;
		}
		//save string form of 'to' ip to add to WinDivert filter
		ipsin.push_back(strto);
		to = byteswap(to);

		//remove from string
		arg = arg.substr(0, eq);

		//start parsing 'from' ips
		comma = arg.find(',');
		while (1) {
			strfrom = arg.substr(0, comma);
			//save each 'from' ip with associated 'to' ip
			if (WinDivertHelperParseIPv4Address(strfrom.c_str(), &from)) {
				from = byteswap(from);
				ipmap[from] = to;

				//save string form of 'from' ip to add to WinDivert filter
				ipsout.push_back(strfrom);
				std::cout << "Adding redirect from " << strfrom << " to " << strto << std::endl;
			} else {
				std::cout << "Unable to parse ip " << strfrom << ": #" << GetLastError() << std::endl;
			}

			//go to next 'from' ip
			if (comma == std::string::npos)
				break;
			arg = arg.substr(comma+1);
			comma = arg.find(',');
		}
	}

	return dbg;
}

//short byteswap
UINT16 byteswap(UINT16 i) {
	UINT16 o;
	UINT8* pi = (UINT8*)&i;
	UINT8* po = (UINT8*)&o;

	po[0] = pi[1];
	po[1] = pi[0];

	return o;
}
//int byteswap
UINT32 byteswap(UINT32 i) {
	UINT32 o;
	UINT8* pi = (UINT8*)&i;
	UINT8* po = (UINT8*)&o;

	po[0] = pi[3];
	po[1] = pi[2];
	po[2] = pi[1];
	po[3] = pi[0];

	return o;
}

//converts big endian formatted 32bit ip into dotted decimal string form
std::string DottedIPv4(UINT32 ip) {
	std::stringstream ss;
	UINT8* pip = (UINT8*)&ip;
	ss << (int)pip[0] << "." << (int)pip[1] << "." << (int)pip[2] << "." << (int)pip[3];
	return ss.str();
}

//return a name for a protocol id
std::string ProtocolName(UINT8 prot) {
	switch (prot) {
		case 0x01: return "ICMP";
		case 0x06: return "TCP";
		case 0x11: return "UDP";
		default: {
			std::stringstream ss;
			ss << "0x" << std::hex << (int)prot;
			return ss.str();
		}
	};
}

//converts nat tuple into string form
std::string DisplayTuple(nattuple_t o) {
	std::stringstream ss;
	ss << "(P: " << ProtocolName(o.protocol) << ", LIP: " << DottedIPv4(o.localip) << ", RIP: " << DottedIPv4(o.remoteip);
	if (o.localport) ss << ", Lp: " << byteswap(o.localport);
	if (o.remoteport) ss << ", Rp: " << byteswap(o.remoteport);
	ss << ")";
	return ss.str();
}

//show usage/help
void usage(const char* arg) {
	std::cout << "ipredir " << VERSION_STR << " by cybermind" << std::endl;
	std::cout << "Will rewrite outgoing packets to redirect which IP they are headed to." << std::endl;
	std::cout << "It will also rewrite the incoming packets back to their original values," << std::endl;
	std::cout << "acting as a rudimentary NAT." << std::endl;
	std::cout << std::endl;
	std::cout << "Usage:" << std::endl;
	std::cout << "\t" << arg << " <rule> [rule...]" << std::endl;
	std::cout << std::endl;
	std::cout << "A rule is of the format:" << std::endl;
	std::cout << "\toldip[,oldip[,oldip[...]]]=newip" << std::endl;
	std::cout << std::endl;
	std::cout << "where any packets headed for 'oldip' will be redirected to 'newip'" << std::endl;
	std::cout << std::endl;
	std::cout << "Examples:" << std::endl;
	std::cout << "\t" << arg << " 1.2.3.4=192.168.1.1" << std::endl;
	std::cout << "\t" << arg << " 1.2.3.4,1.2.3.5=192.168.1.1" << std::endl;
	std::cout << "\t" << arg << " 1.2.3.4,1.2.3.5=192.168.1.1 2.3.4.5=192.168.2.1" << std::endl;
}
