#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_acl.h>
#include <rte_ring.h>
#include <time.h>

#include "rdkafka.h"

#define OFF_ETHHEAD (sizeof(struct rte_ether_hdr))
#define PREFETCH_OFFSET 3
#define OFF_IPV42PROTO (offsetof(struct rte_ipv4_hdr, next_proto_id))
#define MBUF_IPV4_2PROTO(m) \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define RX_RING_SIZE 3096
#define TX_RING_SIZE 128
#define MAX_PKT_BURST 32
#define NUM_MBUFS 65535
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


struct rte_ring *kafka_ring0_0;
struct rte_ring *kafka_ring1_0;
struct rte_ring *kafka_ring2_0;
struct rte_ring *kafka_ring3_0;
struct rte_ring *kafka_ring0_1;
struct rte_ring *kafka_ring1_1;
struct rte_ring *kafka_ring2_1;
struct rte_ring *kafka_ring3_1;
struct rte_ring *kafka_ring0_2;
struct rte_ring *kafka_ring1_2;
struct rte_ring *kafka_ring2_2;
struct rte_ring *kafka_ring3_2;


struct rte_ring *mbuf_ring0;
struct rte_ring *mbuf_ring1;
struct rte_ring *mbuf_ring2;
struct rte_ring *mbuf_ring3;

int CATEGORIES = 1;
int rule_number = 0;
int pac_size_to_catch = 1000000;

void *ring_name[12];
void *mbuf_ring[4];

const char *kafka_topics[4] = {"flow0","flow1","flow2","flow3"};


static void dr_msg_cb (rd_kafka_t *rk,
                       const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr, "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));
//        else
//                fprintf(stderr,
//                        "%% Message delivered (%zd bytes, "
//                        "partition %"PRId32")\n",
//                        rkmessage->len, rkmessage->partition);

        // The rkmessage is destroyed automatically by librdkafka
}


static uint8_t rss_intel_key[40] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
                                   };

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		    .mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
        .rss_conf = {
            .rss_key = rss_intel_key,
	    .rss_key_len = 40,
            .rss_hf = ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP,
        },
    },
};

struct rte_acl_ctx * acx;
struct rte_acl_config cfg;

struct ipv4_5tuple {
    uint8_t proto;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};


struct rte_acl_field_def ipv4_defs[5] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
	 .offset = 0,        
	//.offset = offsetof (struct ipv4_5tuple, proto),
    },

    /* next input field (IPv4 source address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(struct rte_ipv4_hdr, src_addr) -
            offsetof(struct rte_ipv4_hdr, next_proto_id),
	//.offset = offsetof (struct ipv4_5tuple, ip_src),
    },

    /* next input field (IPv4 destination address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
        //.offset = offsetof (struct ipv4_5tuple, ip_dst),
	.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
            offsetof(struct rte_ipv4_hdr, next_proto_id),
    },

    /*
     * Next 2 fields (src & dst ports) form 4 consecutive bytes.
     * They share the same input index.
     */
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 3,
        .input_index = 3,
        //.offset = offsetof (struct ipv4_5tuple, port_src),
	.offset = sizeof(struct rte_ipv4_hdr) -
            offsetof(struct rte_ipv4_hdr, next_proto_id),
    },

    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 4,
        .input_index = 3,
	.offset = sizeof(struct rte_ipv4_hdr) -
            offsetof(struct rte_ipv4_hdr, next_proto_id) +
            sizeof(uint16_t),        
	//.offset = offsetof (struct ipv4_5tuple, port_dst),
    },
};

RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));

struct acl_ipv4_rule acl_rules[8];
struct rte_acl_param prm = {
    .name = "ACL_example",
    .socket_id = SOCKET_ID_ANY,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),

    /* number of fields per rule. */

    .max_rule_num = 8, /* maximum number of rules in the AC context. */
};


struct acl_search_t {
    const uint8_t *data_ipv4[MAX_PKT_BURST];
    struct rte_mbuf *m_ipv4[MAX_PKT_BURST];
    uint32_t res_ipv4[MAX_PKT_BURST * 4];
    int num_ipv4;
};


static inline void
prepare_one_packet(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
    int index)
{
    struct rte_mbuf *pkt = pkts_in[index];
    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        /* Fill acl structure */
        acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
        acl->m_ipv4[(acl->num_ipv4)++] = pkt;
    } else {
    		if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type))
			printf("ipv6\n");
		else{
			printf("unkown\n");
		}
       	rte_pktmbuf_free(pkt);
    }
}


static inline void
prepare_acl_parameter(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
    int nb_rx)
{
    int i;
    acl->num_ipv4 = 0;

    /* Prefetch first packets */
    for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(
                pkts_in[i], void *));
    }
    for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_in[
                i + PREFETCH_OFFSET], void *));
        prepare_one_packet(pkts_in, acl, i);
    }
    /* Process left packets */
    for (; i < nb_rx; i++)
        prepare_one_packet(pkts_in, acl, i);
}





static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 4, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_kafka(void)
{
	rd_kafka_t *rk;         /* Producer instance handle */
        rd_kafka_conf_t *conf;  /* Temporary configuration object */
        char errstr[512];       /* librdkafka API error reporting buffer */
        char *buf;              /* Message value temporary buffer */
        const char *brokers;    /* Argument: broker list */
        const char *topic;      /* Argument: topic to produce to */

	char pac[50000];

	int _id = rte_lcore_id();
	printf("%d core run as kafka producer\n",_id);

	struct rte_ring *kafka_ring;
	kafka_ring = (struct rte_ring *)ring_name[(_id+4)%12];


        brokers = "localhost:9092";
        topic = kafka_topics[_id%4];

	/*
         * Create Kafka client configuration place-holder
         */
        conf = rd_kafka_conf_new();

	rd_kafka_conf_set(conf,"queue.buffering.max.messages", "10000000",NULL,0);
	rd_kafka_conf_set(conf,"queue.buffering.max.kbytes", "3072000",NULL,0);
	rd_kafka_conf_set(conf,"queue.buffering.max.ms","200",NULL,0);
	rd_kafka_conf_set(conf,"linger.ms","200",NULL,0);

	rd_kafka_conf_set(conf,"batch.num.messages","25000",NULL,0);
	rd_kafka_conf_set(conf,"batch.size","10000000",NULL,0);


        /* Set bootstrap broker(s) as a comma-separated list of
         * host or host:port (default port 9092).
         * librdkafka will use the bootstrap brokers to acquire the full
         * set of brokers from the cluster. */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
        }


        /* Set the delivery report callback.
         * This callback will be called once per message to inform
         * the application if delivery succeeded or failed.
         * See dr_msg_cb() above.
         * The callback is only triggered from rd_kafka_poll() and
         * rd_kafka_flush(). */
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

	        /*
         * Create producer instance.
         *
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                fprintf(stderr,
                       "%% Failed to create new producer: %s\n", errstr);         
        }
	
	rd_kafka_resp_err_t err;
	//int pac_saved=0;

	int total_length = 0;
	char *locate = pac;
	int burst_size=0,i=0;

	while(1){
	if(rte_ring_empty(kafka_ring)){
		rd_kafka_poll(rk,0);
		if(total_length!=0){
			goto retry;
		}
		continue;
	}
	struct rte_mbuf *burst_buffer[64] = { NULL };
//	int remain;
	burst_size=rte_ring_dequeue_burst(kafka_ring,(void *)burst_buffer,64,NULL);
//	if(remain > 256 * 32){
//		printf("%d ",remain);
//	}
//
//	for(i=0;i<burst_size;i++){
//		rte_pktmbuf_free(burst_buffer[i]);
//	}
//	continue;


	for(i=0;i<burst_size;){
		buf = rte_pktmbuf_mtod(burst_buffer[i], char *);
        	int len = rte_pktmbuf_pkt_len(burst_buffer[i]);
		
		memcpy(locate,&len,4);

		
		locate+=4;
		total_length+=4;
        	memcpy(locate,buf,len);
		locate+=len;
		burst_buffer[i]->udata64--;
//		if(burst_buffer[i]->udata64 == 0)
        		rte_pktmbuf_free(burst_buffer[i]);
        	total_length+=len;
        	i++;
        	if(total_length<=40960){
        		continue;
        	}
	retry:
              err = rd_kafka_producev(    
                        rk,                 
                        RD_KAFKA_V_TOPIC(topic),                       
                        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),			
                        RD_KAFKA_V_VALUE(pac, total_length),
                    	RD_KAFKA_V_PARTITION((_id+4)%3),		     	
                        RD_KAFKA_V_OPAQUE(NULL),                       
                        RD_KAFKA_V_END);

		if (err) {
                        fprintf(stderr,
                                "%% Failed to produce to topic %s: %s\n",
                                topic, rd_kafka_err2str(err));

                        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                                printf("queue full");
                                rd_kafka_poll(rk, 1000);
                                goto retry;
                        }
                }


		locate = pac;
		total_length = 0;

	}
          rd_kafka_poll(rk, 0/*non-blocking*/);
	}

	fprintf(stderr, "%% Flushing final messages..\n");
        rd_kafka_flush(rk, 10*1000 /* wait for max 10 seconds */);

        /* If the output queue is still not empty there is an issue
         * with producing messages to the clusters. */
        if (rd_kafka_outq_len(rk) > 0)
                fprintf(stderr, "%% %d message(s) were not delivered\n",
                        rd_kafka_outq_len(rk));

        /* Destroy the producer instance */
        rd_kafka_destroy(rk);
	return;
}


static void lcore_acl(void)
{
	struct acl_search_t acl_search;
	int i,_id;
	struct rte_ring *_mbuf_ring;

	_id = rte_lcore_id();
	printf("core %d acl\n",_id);
	_mbuf_ring =(struct rte_ring *) mbuf_ring[_id%4];

	struct rte_mbuf *bufs[32] = { NULL };
	int nb_rx;
	int pac_get=0;
	int pac_acl=0;
	int pac_free=0;
	struct rte_eth_stats stats;


	
	while(1){
		nb_rx=rte_ring_dequeue_burst(_mbuf_ring,(void *)bufs,32,NULL);
		
		if(nb_rx == 0){
			continue;
		}
		
		for(i=0;i<nb_rx*CATEGORIES;i++){
			acl_search.res_ipv4[i]=0;
		}

		prepare_acl_parameter(bufs, &acl_search, nb_rx);
					
		rte_acl_classify_alg(
        		acx,
        		acl_search.data_ipv4,
        	        acl_search.res_ipv4,
        	        acl_search.num_ipv4,
        	        1,
        	        RTE_ACL_CLASSIFY_SCALAR);

        	
//		printf("%d\n",nb_rx);
//		for(i=0;i<nb_rx;i++){
//			rte_pktmbuf_free(bufs[i]);
//		}
//		continue;

		int choice;
		int j;
		
		for(i=0;i<acl_search.num_ipv4;i++){
			choice = acl_search.m_ipv4[i]->hash.rss %3;
			acl_search.m_ipv4[i]->udata64 = 0;
			for(j=0;j<CATEGORIES;j++){
				if(acl_search.res_ipv4[i*CATEGORIES+j]==0){
					rte_pktmbuf_free(acl_search.m_ipv4[i]);
					pac_free++;
					continue;
				}
				if(_id%4==0){
					pac_acl++;
//					acl_search.m_ipv4[i]->udata64++;
					if(choice == 0)
						rte_ring_enqueue(kafka_ring0_0,(void*)acl_search.m_ipv4[i]);
					else if(choice == 1)
						rte_ring_enqueue(kafka_ring0_1,(void*)acl_search.m_ipv4[i]);
					else 
						rte_ring_enqueue(kafka_ring0_2,(void*)acl_search.m_ipv4[i]);
				}
				else if(_id%4==1){
//					acl_search.m_ipv4[i]->udata64++;
					pac_acl++;
					if(choice == 0)
						rte_ring_enqueue(kafka_ring1_0,(void*)acl_search.m_ipv4[i]);
					else if(choice == 1)
						rte_ring_enqueue(kafka_ring1_1,(void*)acl_search.m_ipv4[i]);
					else 
						rte_ring_enqueue(kafka_ring1_2,(void*)acl_search.m_ipv4[i]);
				}
				else if(_id%4==2){
//					acl_search.m_ipv4[i]->udata64++;
					pac_acl++;
					if(choice == 0)
						rte_ring_enqueue(kafka_ring2_0,(void*)acl_search.m_ipv4[i]);
					else if(choice == 1)
						rte_ring_enqueue(kafka_ring2_1,(void*)acl_search.m_ipv4[i]);
					else 
						rte_ring_enqueue(kafka_ring2_2,(void*)acl_search.m_ipv4[i]);
				}
				else if(_id%4==3){
//					acl_search.m_ipv4[i]->udata64++;
					pac_acl++;
					if(choice == 0)
						rte_ring_enqueue(kafka_ring3_0,(void*)acl_search.m_ipv4[i]);
					else if(choice == 1)
						rte_ring_enqueue(kafka_ring3_1,(void*)acl_search.m_ipv4[i]);
					else 
						rte_ring_enqueue(kafka_ring3_2,(void*)acl_search.m_ipv4[i]);
				}
			}
		}
		pac_get+=nb_rx;
			if(pac_get >= pac_size_to_catch){
			memset(&stats, 0, sizeof(stats));
    			rte_eth_stats_get(0, &stats);
    			printf("%ld ipackets %ld imissed %ld ierrors\n",stats.ipackets,stats.imissed,stats.ierrors);
			printf("core %d get %d and acled %d freed %d\n",_id,pac_get,pac_acl,pac_free);
			}
	}
}


static void
lcore_main(void)
{

	int pac_cnt=0;
    uint16_t port;
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
        if (rte_eth_dev_socket_id(port) > 0 &&
                rte_eth_dev_socket_id(port) !=
                        (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", port);
    printf("\nCore %u receiving packets\n",
            rte_lcore_id());


    rte_eth_stats_reset(0);
    int coreid = rte_lcore_id();
    struct rte_ring *_mbuf_ring =(struct rte_ring *) mbuf_ring[coreid];
    /* Run until the application is quit or killed. */

	int i;
	unsigned int res;
     while(true) {
            struct rte_mbuf *bufs[BURST_SIZE];

            const uint16_t nb_rx = rte_eth_rx_burst(0, coreid,
                    bufs, BURST_SIZE);
            if (unlikely(nb_rx == 0))
                continue;
		
        
        if(pac_cnt>=pac_size_to_catch){
        	for(i=0;i<nb_rx;i++){
        		rte_pktmbuf_free(bufs[i]);
        	}
        }
        else{
        		rte_ring_enqueue_burst(_mbuf_ring,(void *)bufs,nb_rx,&res);
        }
        pac_cnt+=nb_rx;
    }
}

static int 
ipv4_5_tuple_parse(void){
	int s_addr0,s_addr1,s_addr2,s_addr3,s_addr_mask;
	int d_addr0,d_addr1,d_addr2,d_addr3,d_addr_mask;
	int s_port,s_port_mask;
	int d_port,d_port_mask;
	int protol,protol_mask;
	int pri,user_data,catg;
	int number = 0;
	FILE *fp;
	fp = fopen("rules.txt","r");
	while(fscanf(fp,"%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d/%x %d/%x %d/%x %d %d %d\n",
	&s_addr0,&s_addr1,&s_addr2,&s_addr3,&s_addr_mask,
	&d_addr0,&d_addr1,&d_addr2,&d_addr3,&d_addr_mask,
	&s_port,&s_port_mask,
	&d_port,&d_port_mask,
	&protol,&protol_mask,
	&pri,&user_data,&catg
	)!=EOF){
		acl_rules[number].data.userdata = user_data;
	//	printf("user_data = %d\n",user_data);
		acl_rules[number].data.category_mask = catg;
		
		printf("catg = %d\n",catg);
		acl_rules[number].data.priority = pri;
	//	printf("pri = %d\n",pri);
	
		acl_rules[number].field[0].value.u8 = protol;
		acl_rules[number].field[0].mask_range.u8 = protol_mask;

	//	printf("%d %x\n",protol,protol_mask);
	
		/* source IPv4 */
         acl_rules[number].field[1].value.u32 = RTE_IPV4(s_addr0,s_addr1,s_addr2,s_addr3);
         acl_rules[number].field[1].mask_range.u32 = s_addr_mask;

	    printf("%d.%d.%d.%d\n",s_addr0,s_addr1,s_addr2,s_addr3);
	    printf("%d\n",s_addr_mask);

        /* destination IPv4 */
	    acl_rules[number].field[2].value.u32 = RTE_IPV4(d_addr0,d_addr1,d_addr2,d_addr3);
         acl_rules[number].field[2].mask_range.u32 = d_addr_mask;

        /* source port */
		acl_rules[number].field[3].value.u16 = s_port;
		acl_rules[number].field[3].mask_range.u16 = s_port_mask;

        /* destination port */
         acl_rules[number].field[4].value.u16 = d_port;
         acl_rules[number].field[4].mask_range.u16 = d_port_mask;
         
	    number ++;	
	}
	fclose(fp);
	return number;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;
    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    printf("%d ports find\n",nb_ports);

    kafka_ring0_0 = rte_ring_create("kafka_ring0_0", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring0_1 = rte_ring_create("kafka_ring0_1", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring1_0 = rte_ring_create("kafka_ring1_0", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring1_1 = rte_ring_create("kafka_ring1_1", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring2_0 = rte_ring_create("kafka_ring2_0", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring2_1 = rte_ring_create("kafka_ring2_1", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring3_0 = rte_ring_create("kafka_ring3_0", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring3_1 = rte_ring_create("kafka-ring3_1", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring0_2 = rte_ring_create("kafka_ring0_2", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring1_2 = rte_ring_create("kafka_ring1_2", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring2_2 = rte_ring_create("kafka_ring2_2", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    kafka_ring3_2 = rte_ring_create("kafka-ring3_2", 256*32, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    mbuf_ring0 = rte_ring_create("mbuf_ring0", 256*64, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    mbuf_ring1 = rte_ring_create("mbuf_ring1", 256*64, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    mbuf_ring2 = rte_ring_create("mbuf_ring2", 256*64, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    mbuf_ring3 = rte_ring_create("mbuf_ring3", 256*64, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    mbuf_ring[0] = mbuf_ring0;
    mbuf_ring[1] = mbuf_ring1;
    mbuf_ring[2] = mbuf_ring2;
    mbuf_ring[3] = mbuf_ring3;

    ring_name[0] = kafka_ring0_0;
    ring_name[1] = kafka_ring1_0;
    ring_name[2] = kafka_ring2_0;
    ring_name[3] = kafka_ring3_0;
    ring_name[4] = kafka_ring0_1;
    ring_name[5] = kafka_ring1_1;
    ring_name[6] = kafka_ring2_1;
    ring_name[7] = kafka_ring3_1;
    ring_name[8] = kafka_ring0_2;
    ring_name[9] = kafka_ring1_2;
    ring_name[10] = kafka_ring2_2;
    ring_name[11] = kafka_ring3_2;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    /* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                    portid);

/* create an empty AC context  */

if ((acx = rte_acl_create(&prm)) == NULL) {
	printf("err in acx\n");
    /* handle context create failure. */

}

/* add rules to the context */
rule_number = ipv4_5_tuple_parse();
ret = rte_acl_add_rules(acx, (const struct rte_acl_rule *)acl_rules, rule_number);
if (ret != 0) {
	printf("err in acl rules");
   /* handle error at adding ACL rules. */
}

/* prepare AC build config. */

//printf("%d categ\n",CATEGORIES);

cfg.num_categories = 4;
cfg.num_fields = RTE_DIM(ipv4_defs);

memcpy(cfg.defs, ipv4_defs, sizeof (ipv4_defs));

/* build the runtime structures for added rules, with 2 categories. */
ret = rte_acl_build(acx, &cfg);
if (ret != 0) {
	printf("err in acl context\n");
   /* handle error at build runtime structures for ACL context. */
}

rte_acl_dump(acx);
	int i;
	for(i=4;i<8;i++)	
		rte_eal_remote_launch((lcore_function_t*)lcore_acl,NULL,i);
		
	for(i =8;i<20;i++){
		rte_eal_remote_launch((lcore_function_t*)lcore_kafka,NULL,i);
	}
	for(i=1;i<4;i++)	
		rte_eal_remote_launch((lcore_function_t*)lcore_main,NULL,i);
	lcore_main();
	return 0;
}
