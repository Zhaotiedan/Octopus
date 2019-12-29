#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include<mysql/mysql.h>

MYSQL *conn_ptr;                           
unsigned int timeout = 7;   //超时时间7秒
#define PORT 3333
#define BACKLOG 1
#define MAXRECVLEN 65535
char trans[MAXRECVLEN];
void change(int i,char tmp[])
{
  int low=i%16;
  int high=i/16;
  if(low<=9)
  {
    tmp[1]='0'+low;                        
  }
  else
  {
    tmp[1]='a'+low-10;                    
  }
  if(high<=9)
  {
    tmp[0]='0'+high;
  }
  else{
    tmp[0]='a'+high-10;               
  }        
}

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  int ret = 0;
  conn_ptr = mysql_init(NULL);//初始化                                            
  if(!conn_ptr)
  {
    printf("mysql_init failed!\n");
    return ;
  }
  ret = mysql_options(conn_ptr,MYSQL_OPT_CONNECT_TIMEOUT,(const char*)&timeout);//设置超时>    选项
  if(ret) 
  {
    printf("Options Set ERRO!\n");                        
  }
  conn_ptr = mysql_real_connect(conn_ptr,"192.168.43.172","root","root","Packet",0,NULL,0);//连接MySQ
  if(conn_ptr)
  {
    printf("Connection Succeed!\n");         
  }
  int *count = (int *)arg;          
  printf("Packet Count: %d\n", ++(*count));
  printf("Received Packet Size: %d\n", pkthdr->len);
  printf("Payload:\n");
  int i=0;
  int j=0;
  char tmp[2];
  memset(trans,0,MAXRECVLEN);
  for( i=0; i < pkthdr->len; ++i)
  {
    change((int)packet[i],tmp);
    trans[j++]=tmp[0];
    trans[j++]=tmp[1];
    trans[j++]=' ';
    printf("%02x ", packet[i]);
    if ((i + 1) % 16 == 0)
      printf("\n"); 
  }
  printf("transInProcess=%s\n\n",trans);
  char sql_insert[2000];
  sprintf(sql_insert,"insert into Packet(id,time,packet) VALUES(2,now(),'%s');",trans);                  
  mysql_query(conn_ptr,sql_insert);
  if(!ret)
  {
  printf("Inserted %lu rows\n",(unsigned long)mysql_affected_rows(conn_ptr));//返回上次UPDATE更改行数
  }
  else
  {
    printf("Connect Erro:%d %s\n",mysql_errno(conn_ptr),mysql_error(conn_ptr));//返回错误代码、错误消息
  
  }
}
int Get()
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];
  /* 获取本地机器设备列表 */
  if (pcap_findalldevs( &alldevs, errbuf    ) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
    exit(1);                                                                
  }
  for(d= alldevs; d != NULL; d= d->next)
  {
    if(strcmp(d->name,"ens33")==0)
    {   
      printf("%d. %s", ++i, d->name);
      break;
    }
  }
  devStr=d->name;
  if (devStr)
    printf("success: device: %s\n", devStr);
  else
  {
    printf("error: %s\n", errBuf);
    exit(1);
  }
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
  if (!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);                                                   
  }
  /* construct a filter */
  struct bpf_program filter;
  pcap_compile(device, &filter, "ip", 1, 0);
  pcap_setfilter(device, &filter);
  int count = 0;
  /*Loop forever & call processPacket() for every received pa      cket.*/
  pcap_loop(device, 1, processPacket, (u_char *)&count);
  printf("transInGet=%s\n\n",trans);
  pcap_close(device);                                                                return 0; 
}  

int main(int argc, char *argv[])
{
   Get();
   return 0;
}
