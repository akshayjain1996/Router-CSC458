/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0
#define ICMP_DEST_NET_UNREACHABLE_TYPE 3
#define ICMP_DEST_NET_UNREACHABLE_CODE 0
#define ICMP_DEST_HOST_UNREACHABLE_TYPE 3
#define ICMP_DEST_HOST_UNREACHABLE_CODE 1
#define ICMP_PORT_UNREACHABLE_TYPE 3
#define ICMP_PORT_UNREACHABLE_CODE 3
#define ICMP_TIME_EXCEEDED_TYPE 11
#define ICMP_TIME_EXCEEDED_CODE 0

void handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void forward_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len);
void handel_icmp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, int type, int code);
void handle_echo_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_type3(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, int code);
void handle_type11(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, int code);
struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t next_hop_ip);
void encap_and_send(struct sr_instance* sr, uint8_t * response_packet, unsigned int len, struct sr_rt *next_hop);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */


  /* Check the ethertype of packet and handel accordingly.*/
  switch(ethertype(packet)){

    case ethertype_arp : 
      printf("*** -> ARP package\n");
      handle_arp_packet(sr, packet, len, interface);

      break;

    case ethertype_ip :
      printf("*** -> IP package \n");
      handle_ip_packet(sr, packet, len, interface);
      break;

  }

}

void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(!find_longest_prefix_match(sr, iphdr->ip_dst)){

    switch(iphdr -> ip_p){
      case ip_protocol_icmp:
        handel_icmp_packet(sr, packet, len, interface, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REPLY_CODE);
        break;

      default:
        handel_icmp_packet(sr, packet, len, interface, ICMP_PORT_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE);
        break;
    }

  } else {
    /* Forward packet.*/
    if(iphdr->ip_ttl <= 1){
      /* drop packet */
      handel_icmp_packet(sr, packet, len, interface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
      return;
    } 
    forward_ip_packet(sr, packet, len);
  }

}


void forward_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len){

  uint8_t *response_packet = malloc(len);
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_rt *next_hop = find_longest_prefix_match(sr, iphdr->ip_dst);

  memcpy(response_packet, packet, len);
  sr_ethernet_hdr_t *resp_ehdr = (sr_ethernet_hdr_t *) response_packet;
  sr_ip_hdr_t *resp_iphdr = (sr_ip_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t));
  
  resp_iphdr->ip_ttl--;
  resp_iphdr->ip_sum = 0;
  resp_iphdr->ip_sum = cksum((void *)resp_iphdr, sizeof(sr_ip_hdr_t));

  struct sr_if *interface = sr_get_interface(sr, next_hop -> interface);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop->gw.s_addr);

  if (arp_entry) {
    memcpy(resp_ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(resp_ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, response_packet, len, next_hop->interface);
    free(arp_entry);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop->gw.s_addr, response_packet, len, next_hop->interface);
    sr_handle_arpreq(sr, req);
  }

  free(response_packet);

}

struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t next_hop_ip) {
  struct sr_rt *longest_prefix_match;
  struct sr_rt *current_entry;
  uint32_t current_entry_prefix;
  uint32_t current_mask;
  uint32_t dest_ip_prefix;

  longest_prefix_match = 0;
  current_entry = sr->routing_table;

  while (current_entry) {
    current_mask = current_entry->mask.s_addr;
    current_entry_prefix = current_entry->dest.s_addr & current_mask;
    dest_ip_prefix = next_hop_ip & current_mask;

    if (current_entry_prefix == dest_ip_prefix &&
        (!longest_prefix_match || current_mask > longest_prefix_match->mask.s_addr)) {
      longest_prefix_match = current_entry;
    }

    current_entry = current_entry->next;
  }

  return longest_prefix_match;
}


void handel_icmp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, int type, int code){
  switch (type){
    case ICMP_ECHO_REPLY_TYPE:
      printf("*** -> Echo Type \n");
      handle_echo_reply(sr, packet, len, interface);
      break;

    case ICMP_PORT_UNREACHABLE_TYPE || ICMP_DEST_NET_UNREACHABLE_TYPE || ICMP_DEST_HOST_UNREACHABLE_TYPE:
      printf("*** -> Unreachable - Type 3 \n");
      handle_type3(sr, packet, len, interface, code);
      break;

    case ICMP_TIME_EXCEEDED_TYPE:
      printf("*** -> Time Exceeded - Type 11 \n");
      handle_type11(sr, packet, len, interface, code);
      break;
  }
}

void handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
    
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  switch(ntohs(arphdr->ar_op)){
    case arp_op_request:
      handle_arp_request(sr, packet, len, interface);
      break;

    case arp_op_reply:
      handle_arp_reply(sr, packet, len, interface);
      break;
  }

}

void handle_arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("*** -> Request\n");

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if *in_iface = sr_get_interface(sr, interface);

  unsigned int response_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t); 

  uint8_t *response_packet = (uint8_t *) malloc(response_packet_len); 
  sr_ethernet_hdr_t *resp_ehdr = (sr_ethernet_hdr_t *) response_packet;
  sr_arp_hdr_t *resp_arphdr = (sr_arp_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t));

  memcpy(resp_ehdr -> ether_shost, in_iface -> addr, sizeof(resp_ehdr -> ether_dhost));
  memcpy(resp_ehdr -> ether_dhost, ehdr -> ether_dhost, sizeof(resp_ehdr -> ether_shost));
  resp_ehdr->ether_type = ehdr->ether_type;

  resp_arphdr->ar_hrd = arphdr->ar_hrd;      
  resp_arphdr->ar_pro = arphdr->ar_pro;     
  resp_arphdr->ar_hln = arphdr->ar_hln;    
  resp_arphdr->ar_pln = arphdr->ar_pln;      
  resp_arphdr->ar_op  = htons(arp_op_reply);  
  resp_arphdr->ar_sip = in_iface->ip;  
  resp_arphdr->ar_tip = arphdr->ar_sip;      

  memcpy(resp_arphdr->ar_sha, in_iface->addr, ETHER_ADDR_LEN); 
  memcpy(resp_arphdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);  

  sr_send_packet(sr, response_packet, response_packet_len, in_iface->name);
  free(response_packet);
}

void handle_arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("*** -> Reply\n");

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)( packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if *rec_if = sr_get_interface(sr, interface);

  if (rec_if->ip != arphdr->ar_tip){
    return;
  }

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, arphdr->ar_sip);

  if(arp_entry == 0){
    struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);
    if(arp_req != 0){
      struct sr_packet *pkts = NULL;
      struct sr_if *dest_if = NULL;
      sr_ethernet_hdr_t *pkt_eth_hdr = NULL; 
      
      pkts = arp_req->packets;
      while(pkts)
      {
        pkt_eth_hdr = (sr_ethernet_hdr_t *)(pkts->buf);
        dest_if = sr_get_interface(sr, pkts->iface);

        memcpy(pkt_eth_hdr->ether_shost, dest_if->addr, sizeof(pkt_eth_hdr->ether_shost));
        memcpy(pkt_eth_hdr->ether_dhost, arphdr->ar_sha, sizeof(pkt_eth_hdr->ether_dhost));
        sr_send_packet(sr, pkts->buf, pkts->len, pkts->iface);
        pkts = pkts->next;
      }

      sr_arpreq_destroy(&(sr->cache), arp_req);

    }
  }

  free(arp_entry);
}

void handle_echo_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* iface){
  uint8_t * response_packet = malloc(len);

  memcpy(response_packet, packet, len);
  /* Make response ethernet header.*/
  sr_ip_hdr_t *iphrd = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)); 
  struct sr_rt *next_hop = find_longest_prefix_match(sr, iphrd->ip_dst);
  /* Make response ip header.*/
  sr_ip_hdr_t *resp_iphrd = (sr_ip_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t));  
  memcpy(resp_iphrd -> ip_src, iphrd -> ip_dst, sizeof(uint8_t));
  memcpy(resp_iphrd -> ip_dst, iphrd -> ip_src, sizeof(uint8_t));
  resp_iphrd -> ip_sum = 0;
  resp_iphrd -> ip_sum = cksum((void *) resp_iphrd, sizeof(sr_ip_hdr_t));   /* or 20. */
  sr_icmp_hdr_t* resp_icmphdr = (sr_icmp_hdr_t *) (response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  resp_icmphdr -> icmp_sum = 0;
  resp_icmphdr -> icmp_type = ICMP_ECHO_REPLY_TYPE;
  resp_icmphdr -> icmp_code = ICMP_ECHO_REPLY_CODE;
  resp_icmphdr -> icmp_sum = cksum((void *)resp_icmphdr, sizeof(sr_icmp_hdr_t));
  encap_and_send(sr, response_packet, len, next_hop);
  free(response_packet);

}

void encap_and_send(struct sr_instance* sr, uint8_t * response_packet, unsigned int len, struct sr_rt *next_hop){
  struct sr_if *interface = sr_get_interface(sr, next_hop -> interface);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop->gw.s_addr);
  sr_ethernet_hdr_t *resp_ehdr = (sr_ethernet_hdr_t *) response_packet;
  resp_ehdr->ether_type = htons(ethertype_ip);
  if (arp_entry) {
    memcpy(resp_ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(resp_ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, response_packet, len, next_hop->interface);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop->gw.s_addr, response_packet, len, next_hop->interface);
    sr_handle_arpreq(sr, req);
  } 
}

void handle_type3(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* iface, int code){
  printf("*** -> Inside type3\n");
  int response_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t * response_packet = (uint8_t *) malloc(response_packet_len);

  sr_ip_hdr_t *iphrd = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  /* Make response ethernet header.*/
  struct sr_rt *next_hop = find_longest_prefix_match(sr, iphrd->ip_dst);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop->gw.s_addr);

  /* Make response ip header.*/
  sr_ip_hdr_t *resp_iphrd = (sr_ip_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t)); 
    
  memcpy(resp_iphrd, iphrd, sizeof(sr_ip_hdr_t));

  memcpy(resp_iphrd -> ip_src, iphrd -> ip_dst, sizeof(uint32_t));
  memcpy(resp_iphrd -> ip_dst, iphrd -> ip_src, sizeof(uint32_t));
  resp_iphrd -> ip_sum = 0;
  resp_iphrd -> ip_sum = cksum((void *) resp_iphrd, sizeof(sr_ip_hdr_t));   /* or 20. */
  sr_icmp_t3_hdr_t* resp_icmphdr = (sr_icmp_t3_hdr_t *) (response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  resp_icmphdr -> icmp_sum = 0;
  resp_icmphdr -> icmp_type = ICMP_PORT_UNREACHABLE_TYPE;
  resp_icmphdr -> icmp_code = code;
  resp_icmphdr -> icmp_sum = cksum((void *)resp_icmphdr, sizeof(sr_icmp_t3_hdr_t));
  
encap_and_send(sr, response_packet, len, next_hop);
  free(response_packet);
}

void handle_type11(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, int code){ 
  unsigned int newlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
  uint8_t *response_packet = (uint8_t *)malloc(newlen);

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  sr_ip_hdr_t *resp_iphrd = (sr_ip_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t *resp_icmphdr = (sr_icmp_t11_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

  resp_icmphdr->icmp_type = ICMP_TIME_EXCEEDED_TYPE;
  resp_icmphdr->icmp_code = 0;
  memcpy(resp_icmphdr->data, iphdr, ICMP_DATA_SIZE);
  resp_icmphdr->icmp_sum = 0;
  resp_icmphdr->icmp_sum = cksum(resp_icmphdr, sizeof(sr_icmp_t11_hdr_t));

  struct sr_if *iface = sr_get_interface(sr, interface);
  memcpy(resp_iphrd, iphdr, sizeof(sr_ip_hdr_t));
  resp_iphrd->ip_tos = 0;
  resp_iphrd->ip_p = ip_protocol_icmp;
  resp_iphrd->ip_ttl = INIT_TTL;
  resp_iphrd->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  resp_iphrd->ip_src = iface->ip;          
  resp_iphrd->ip_dst = iphdr->ip_src;
  resp_iphrd->ip_sum = 0;
  resp_iphrd->ip_sum = cksum(resp_iphrd, iphdr->ip_hl * 4);


  struct sr_rt *next_hop = find_longest_prefix_match(sr, iphdr->ip_src);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, resp_iphrd->ip_dst);
encap_and_send(sr, response_packet, len, next_hop);
}

