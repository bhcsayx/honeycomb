#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>
#include <honeyd/hooks.h>
#include "honeycomb.h"
#include "hc_ip.h"
#include "hc_udp.h"
#include "hc_udp_conn.h"
#include "hc_tcp.h"
#include "hc_tcp_conn.h"
#include "hc_signature.h"
#include "hc_signature_hist.h"
#include "hc_snort_printer.h"
#include "hc_file_logger.h"
#include "hc_config.h"
#define BUFSIZE 10240
#define STRSIZE 1024
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;
//pacp�ļ�ͷ�ṹ��
struct pcap_file_header
{
bpf_u_int32 magic;       /* 0xa1b2c3d4 */
u_short version_major;   /* magjor Version 2 */
u_short version_minor;   /* magjor Version 4 */
bpf_int32 thiszone;      /* gmt to local correction */
bpf_u_int32 sigfigs;     /* accuracy of timestamps */
bpf_u_int32 snaplen;     /* max length saved portion of each pkt */
bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */
};
//ʱ���
struct time_val
{
long tv_sec;         /* seconds ����ͬ time_t �����ֵ */
long tv_usec;        /* and microseconds */
};
//pcap���ݰ�ͷ�ṹ��
struct pcap_pkthdr
{
struct time_val ts;  /* time stamp */
bpf_u_int32 caplen; /* length of portion present */
bpf_u_int32 len;    /* length this packet (off wire) */
};
//����֡ͷ
typedef struct FramHeader_t
{ //Pcap���������֡ͷ
u_int8 DstMAC[6]; //Ŀ��MAC��ַ
u_int8 SrcMAC[6]; //ԴMAC��ַ
u_short FrameType;    //֡����
} FramHeader_t;
//IP���ݱ�ͷ
typedef struct IPHeader_t
{ //IP���ݱ�ͷ
u_int8 Ver_HLen;       //�汾+��ͷ����
u_int8 TOS;            //��������
u_int16 TotalLen;       //�ܳ���
u_int16 ID; //��ʶ
u_int16 Flag_Segment;   //��־+Ƭƫ��
u_int8 TTL;            //��������
u_int8 Protocol;       //Э������
u_int16 Checksum;       //ͷ��У���
u_int32 SrcIP; //ԴIP��ַ
u_int32 DstIP; //Ŀ��IP��ַ
} IPHeader_t;
//IP���ݱ�ͷ
typedef struct TCPHeader_t
{ //TCP���ݱ�ͷ
u_int16 SrcPort; //Դ�˿�
u_int16 DstPort; //Ŀ�Ķ˿�
u_int32 SeqNO; //���
u_int32 AckNO; //ȷ�Ϻ�
u_int8 HeaderLen; //���ݱ�ͷ�ĳ���(4 bit) + ����(4 bit)
u_int8 Flags; //��ʶTCP��ͬ�Ŀ�����Ϣ
u_int16 Window; //���ڴ�С
u_int16 Checksum; //У���
u_int16 UrgentPointer;  //����ָ��
}TCPHeader_t;
typedef struct UDPHeader_t
{//UDP���ݱ�ͷ
u_int16 SrcPort;
u_int16 DstPort;
u_int16 TotalLen;
u_int16 CheckSum;
}UDPHeader_t;
void hc_pcap_handler(char * file)
{
    struct pcap_file_header *file_header;
    struct pcap_pkthdr *ptk_header;
    IPHeader_t *ip_header;
    TCPHeader_t *tcp_header;
    UDPHeader_t *udp_header;
    FILE *fp;
    int pkt_offset,i=0;
    int ip_len,ip_proto;
    int src_port,dst_port,tcp_flags;
    char buf[BUFSIZE], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
    memset(buf, 0, sizeof(buf));
    u_int32 target;
    if((fp = fopen(file,"r")) == NULL)
    {
	printf("error: can not open pcap file\n");
	exit(0);
    }
    pkt_offset = 24; //pcap�ļ�ͷ�ṹ 24���ֽ�
while(fseek(fp, pkt_offset, SEEK_SET) == 0) //�������ݰ�
{
	i++;
	//pcap_pkt_header 16 byte
	if(fread(ptk_header, 16, 1, fp) != 1) //��pcap���ݰ�ͷ�ṹ
	{
		printf("\nread end of pcap file\n");
		break;
	}
	pkt_offset += 16 + ptk_header->caplen;   //��һ�����ݰ���ƫ��ֵ
	//strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime(&(ptk_header->ts.tv_sec))); //��ȡʱ��
	// printf(��%d: %s\n��, i, my_time);
	//����֡ͷ 14�ֽ�
	fseek(fp, 14, SEEK_CUR); //��������֡ͷ
	//IP���ݱ�ͷ 20�ֽ�
	if(fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)
	{
		printf("%d: can not read ip_header\n", i);
		continue;
	}
	if(i==2) target=ip_header->DstIP;
	inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
	inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);
	ip_proto = ip_header->Protocol;
	ip_len = ip_header->TotalLen; //IP���ݱ��ܳ���
	// printf(��%d:  src=%s\n��, i, src_ip);
	if(ip_header->DstIP==target)
        	hc_ip_hook((char*)ip_header,ip_header->Ver_HLen%16,(void*)HD_INCOMING);
	else //(ip_header->SrcIP==target)
		hc_ip_hook((char*)ip_header,ip_header->Ver_HLen%16,(void*)HD_OUTGOING);
    if(ip_proto == 0x06) //�ж��Ƿ��� TCP Э��
    {
         if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
        {
            printf("%d: can not read tcp_header\n", i);
            break;
        }
	if(ip_header->DstIP==target)
        tcp_hook((char*)tcp_header,ip_header->TotalLen-ip_header->Ver_HLen/16,(void*)HD_INCOMING);
	else //if(ip_header->SrcIP==target)
	tcp_hook((char*)tcp_header,ip_header->TotalLen-ip_header->Ver_HLen/16,(void*)HD_OUTGOING);
    }
    if(ip_proto==0x11)  //�ж��Ƿ��� UDP Э��
    {
         if(fread(udp_header,sizeof(UDPHeader_t),1,fp) != 1)
         {
             printf("%d: can not read udp_header\n", i);
             break;
         }
	if(ip_header->DstIP==target)
         udp_hook((char*)udp_header,udp_header->TotalLen,(void*)HD_INCOMING);
	else //if(ip_header->SrcIP==target)
	 udp_hook((char*)udp_header,udp_header->TotalLen,(void*)HD_OUTGOING);
    }
}
}
