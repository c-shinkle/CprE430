#define RETSIGTYPE void
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void printARPHeader(const u_char *p);
void printIPHeader(const u_char *p);
void printICMPHeader(const u_char *p);
void printTCPHeader(const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;

int num_ip_packets = 0;
int num_arp_packets = 0;
int num_icmp_packets = 0;
int num_broadcast_packets = 0;
int num_tcp_packets = 0;
int num_udp_packets = 0;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int main(int argc, char **argv) {
  int cnt, op, i, done = 0;
  bpf_u_int32 localnet, netmask;
  char *cp, *cmdbuf, *device;
  struct bpf_program fcode;
  void (*oldhandler)(int);
  u_char *pcap_userdata;
  char ebuf[PCAP_ERRBUF_SIZE];

  cnt = -1;
  device = NULL;

  if ((cp = strrchr(argv[0], '/')) != NULL)
    program_name = cp + 1;
  else
    program_name = argv[0];

  opterr = 0;
  while ((i = getopt(argc, argv, "pa")) != -1) {
    switch (i) {
    case 'p':
      pflag = 1;
      break;
    case 'a':
      aflag = 1;
      break;
    case '?':
    default:
      done = 1;
      break;
    }
    if (done)
      break;
  }
  if (argc > (optind))
    cmdbuf = copy_argv(&argv[optind]);
  else
    cmdbuf = "";

  if (device == NULL) {
    device = pcap_lookupdev(ebuf);
    if (device == NULL)
      error("%s", ebuf);
  }
  pd = pcap_open_live(device, snaplen, 1, 1000, ebuf);
  if (pd == NULL)
    error("%s", ebuf);
  i = pcap_snapshot(pd);
  if (snaplen < i) {
    warning("snaplen raised from %d to %d", snaplen, i);
    snaplen = i;
  }
  if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
    localnet = 0;
    netmask = 0;
    warning("%s", ebuf);
  }
  /*
   * Let user own process after socket has been opened.
   */
  setuid(getuid());

  if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
    error("%s", pcap_geterr(pd));

  (void)setsignal(SIGTERM, program_ending);
  (void)setsignal(SIGINT, program_ending);
  /* Cooperate with nohup(1) */
  if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
    (void)setsignal(SIGHUP, oldhandler);

  if (pcap_setfilter(pd, &fcode) < 0)
    error("%s", pcap_geterr(pd));
  pcap_userdata = 0;
  (void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
  if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
    (void)fprintf(stderr, "%s: pcap_loop: %s\n", program_name, pcap_geterr(pd));
    exit(1);
  }
  pcap_close(pd);
  exit(0);
}

/* routine is executed on exit */
void program_ending(int signo) {
  struct pcap_stat stat;

  if (pd != NULL && pcap_file(pd) == NULL) {
    (void)fflush(stdout);
    putc('\n', stderr);
    if (pcap_stats(pd, &stat) < 0)
      (void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
    else {
      (void)fprintf(stderr, "%d packets received by filter\n", stat.ps_recv);
      (void)fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
    }
  }
  printf("%d IP packets were printed out\n", num_ip_packets);
  printf("%d ARP packets were printed out\n", num_arp_packets);
  printf("%d broadcast packets were printed out\n", num_broadcast_packets);
  printf("%d ICMP packets were printed out\n", num_icmp_packets);
  printf("%d TCP packets were printed out\n", num_tcp_packets);
  printf("%d UDP packets were printed out\n", num_udp_packets);
  exit(0);
}

/* Like default_print() but data need not be aligned */
void default_print_unaligned(register const u_char *cp, register u_int length) {
  register u_int i, s;
  register int nshorts;

  nshorts = (u_int)length / sizeof(u_short);
  i = 0;
  while (--nshorts >= 0) {
    if ((i++ % 8) == 0)
      (void)printf("\n\t\t\t");
    s = *cp++;
    (void)printf(" %02x%02x", s, *cp++);
  }
  if (length & 1) {
    if ((i % 8) == 0)
      (void)printf("\n\t\t\t");
    (void)printf(" %02x", *cp);
  }
}

/*
 * By default, print the packet out in hex.
 */
void default_print(register const u_char *bp, register u_int length) {
  register const u_short *sp;
  register u_int i;
  register int nshorts;

  if ((long)bp & 1) {
    default_print_unaligned(bp, length);
    return;
  }
  sp = (u_short *)bp;
  nshorts = (u_int)length / sizeof(u_short);
  i = 0;
  while (--nshorts >= 0) {
    if ((i++ % 8) == 0)
      (void)printf("\n\t");
    (void)printf(" %04x", ntohs(*sp++));
  }
  if (length & 1) {
    if ((i % 8) == 0)
      (void)printf("\n\t");
    (void)printf(" %02x", *(u_char *)sp);
  }
}

void printARPHeader(const u_char *p) {
  int hw_type = (p[14] << 8) | p[15];
  printf("Hardware Type = %d\n", hw_type);

  int prot_type = (p[16] << 8) | p[17];
  printf("Protocol Type = %d\n", prot_type);

  printf("Hardware Length = %d\n", p[18]);

  printf("Protocol Length  = %d\n", p[19]);

  int oper = (p[20] << 8) | p[21];
  printf("Operation = %d\n", oper);

  printf("Sender Hardware Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[22],
         p[23], p[24], p[25], p[26], p[27]);

  printf("Sender IP Address = %03d.%03d.%03d.%03d\n", p[28], p[29], p[30],
         p[31]);

  printf("Target Hardware Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[32],
         p[33], p[34], p[35], p[36], p[37]);

  printf("Target IP Address = %03d.%03d.%03d.%03d\n", p[38], p[39], p[40],
         p[41]);
}

void printIPHeader(const u_char *p) {
  printf("Version = %d\n", p[14] >> 4);
  printf("Header Length = %d\n", p[14] & 0x0f);
  printf("Type of Service = %d\n", p[15]);

  int length = (p[16] << 8) | p[17];
  printf("Payload length = %d\n", length);

  int identifier = (p[18] << 8) | p[19];
  printf("Identifier = %d\n", identifier);

  int df = (p[20] & 0x40) ? 1 : 0;
  int mf = (p[20] & 0x20) ? 1 : 0;
  printf("Flags = 0, %d, %d\n", df, mf);

  int frag_offset = ((p[20] & 0x1f) << 8) | p[21];
  printf("Fragment Offset = %d\n", frag_offset);
  printf("Time to Live = %d\n", p[22]);

  int protocol = p[23];
  printf("Protocol = %d\n", protocol);

  int check = (p[24] << 8) | p[25];
  printf("Checksum = %d\n", check);
  // source bytes 26 - 29
  printf("IP Address = %03d.%03d.%03d.%03d\n", p[26], p[27], p[28], p[29]);
  // destination bytes 30 - 33
  if (protocol == 1) {
    printICMPHeader(p);
    num_icmp_packets++;
  } else if (protocol == 6) {
    printTCPHeader(p);
    num_tcp_packets++;
  } else if (protocol == 17) {
    num_udp_packets++;
  }
}

void printICMPHeader(const u_char *p) {
  printf("ICMP Header:\n");
  printf("Type = %d\n", p[34]);
  printf("Code = %d\n", p[35]);

  int check = (p[36] << 8) | p[37];
  printf("Checksum = %d\n", check);
}

void printTCPHeader(const u_char *p) {
  printf("TCP Header:\n");

  int src_port = (p[34] << 8) | p[35];
  printf("Source Port Number = %d\n", src_port);

  int dest_port = (p[36] << 8) | p[37];
  printf("Destination Port Number = %d\n", dest_port);

  int sequ_num = p[38] << 24 | p[39] << 16 | p[40] << 8 | p[41];
  printf("Sequence Number = %d\n", sequ_num);

  int ackn_num = p[42] << 24 | p[43] << 16 | p[44] << 8 | p[45];
  printf("Acknowledgement Number = %d\n", ackn_num);

  int hdr_len = p[46] << 4;
  printf("Header Length = %d\n", hdr_len);

  int flags = p[47] & 0x3f;
  printf("Flags = %d\n", flags);

  int win_size = (p[48] << 8) | p[49];
  printf("Window Size = %d\n", win_size);

  int check = (p[50] << 8) | p[51];
  printf("Checksum = %d\n", check);

  int urg_ptr = (p[52] << 8) | p[53];
  printf("Urgent Pointer = %d\n", urg_ptr);
}

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
  u_int length = h->len;
  u_int caplen = h->caplen;

  printf("------------------------------------------------\n");

  printf("DEST Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[0], p[1], p[2],
         p[3], p[4], p[5]);

  printf("SOURCE Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[6], p[7], p[8],
         p[9], p[10], p[11]);

  uint16_t e_type = ntohs((uint16_t) * &p[12]);

  printf("Type = 0x%04X\n", e_type);

  if (e_type == 0x800) {
    printf("Payload = IP\n");
    num_ip_packets++;
    printIPHeader(p);
  } else if (e_type == 0x806) {
    printf("Payload = ARP\n");
    printARPHeader(p);
    num_arp_packets++;
  } else {
    num_broadcast_packets++;
  }

  default_print(p, caplen);
  putchar('\n');
  putchar('\n');
}
