#ifndef CM_IPREDIR_H
#define CM_IPREDIR_H

//types:
//oldip->newip mapping
typedef std::unordered_map<UINT32, UINT32> ipmap_t;
//protocol/ip/ip/port/port nat tuple
struct nattuple_t {
	UINT8 protocol; UINT32 localip; UINT32 remoteip; UINT16 localport; UINT16 remoteport;
	//comparison functions for containers
	bool operator<(const nattuple_t& o) const {	return memcmp(this, &o, sizeof(o))<0; }
	bool operator==(const nattuple_t& o) const { return memcmp(this, &o, sizeof(o))==0; }
};
//nat mapping
typedef std::unordered_map<nattuple_t, UINT32> natmap_t;

//main worker thread. receives captured packets, possibly modifies, and reinjects them
DWORD redirThread(LPVOID arg);

//given outbound/inbound lists of ips, make a WinDivert filter
std::string makeFilter(std::vector<std::string> ipsout, std::vector<std::string> ipsin);

//parse argument string and return various info
int parseArgs(std::vector<std::string> args, ipmap_t& map, std::vector<std::string>& ipsout, std::vector<std::string>& ipsin);

//short byteswap
UINT16 byteswap(UINT16 i);

//int byteswap
UINT32 byteswap(UINT32 i);

//converts big endian formatted 32bit ip into dotted decimal string form
std::string DottedIPv4(UINT32 ip);

//return a name for a protocol id
std::string ProtocolName(UINT8 prot);

//converts nat tuple into string form
std::string DisplayTuple(nattuple_t o);

//show usage/help
void usage(const char* arg);

#define MAXBUF			0xFFFF		//max packet size

//create a hash function for our tuple type so it can be put in an unordered_map
namespace std {
	template <>
	struct hash<nattuple_t> {
		std::size_t operator()(const nattuple_t& tup) const {
			return	std::hash<UINT32>()(tup.localip)
					^ std::hash<UINT32>()(tup.remoteip)
					^ std::hash<UINT32>()((tup.localport << 16) + tup.remoteport)
					^ std::hash<UINT8>()(tup.protocol);
		}
	};
}

#endif //CM_IPREDIR_H
