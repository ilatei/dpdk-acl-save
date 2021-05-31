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
#define RX_RING_SIZE 4096
#define TX_RING_SIZE 128
#define MAX_PKT_BURST 32
#define NUM_MBUFS 65535
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


//配置系统参数
struct config{
	int CATEGORIES;
	int rule_number;
	int pac_size_to_catch;
	int pipeline_num;
	int partition_use;
	int enable_lru;
	struct rte_ring *mbuf_ring[10];
	struct rte_ring *lru_ring[10];
	struct rte_ring *kafka_ring[40];
};
struct config global_conf;

//Kafka生产者回调函数
static void dr_msg_cb (rd_kafka_t *rk,
                       const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr, "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));
       else
               fprintf(stderr,
                       "%% Message delivered (%zd bytes, "
                       "partition %"PRId32")\n",
                       rkmessage->len, rkmessage->partition);

        //The rkmessage is destroyed automatically by librdkafka
}

//对称rss key
static uint8_t rss_intel_key[40] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
                                     0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
                                   };

// 网卡设置，指定五元组，使用rss
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

// 定义匹配区域，各区域的匹配模式、长度、在数据包中的偏移
struct rte_acl_field_def ipv4_defs[5] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
	    .offset = 0,        
    },

    /* next input field (IPv4 source address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(struct rte_ipv4_hdr, src_addr) -
            offsetof(struct rte_ipv4_hdr, next_proto_id),
    },

    /* next input field (IPv4 destination address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
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

// 匹配时使用的数据结构
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

// 匹配预处理，丢弃未知报文，预取报文
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

// 网卡初始化
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = global_conf.pipeline_num, tx_rings = 1;
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

	printf("rx capa:%lx\n",dev_info.rx_offload_capa);
    printf("tx capa:%lx\n",dev_info.tx_offload_capa);
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
    /* Allocate and set up n RX queue per Ethernet port. */
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

// 每秒输出一次网卡信息
static void
lcore_info(void){
	struct rte_eth_stats stats;
	time_t lt0,lt;
	lt0 = time(&lt0);
	while(1){
		lt = time(&lt);
		if(lt-lt0 > 1){
    			rte_eth_stats_get(0, &stats);
    			printf("%ld ipackets %ld imissed %ld ierrors %ld ibytes\n",stats.ipackets,stats.imissed,stats.ierrors,stats.ibytes);
    			lt0 = lt;
		}	
	}	
}

// Kafka生产者线程
static void
lcore_kafka(void)
{
	rd_kafka_t *rk;         /* Producer instance handle */
    rd_kafka_conf_t *conf;  /* Temporary configuration object */
    char errstr[512];       /* librdkafka API error reporting buffer */
    char *buf;              /* Message value temporary buffer */
    const char *brokers;    /* Argument: broker list */
    const char *topic;      /* Argument: topic to produce to */

	char pac[43000];

	int coreid = rte_lcore_id();
	int pipe = global_conf.pipeline_num;
	int partition = global_conf.partition_use;
	coreid -= pipe*3;
	printf("%d core run as kafka producer to partition %d\n",coreid,coreid%partition);
	struct rte_ring * _kafka_ring = (struct rte_ring *)global_conf.kafka_ring[coreid%(pipe*partition)];


    brokers = "localhost:9092";
    const char *kafka_topics[8] = {"single0","single1","single2","single3","single4","single5","single6","single7"};
    topic = kafka_topics[coreid/partition];

	/*
         * Create Kafka client configuration place-holder
     */
    conf = rd_kafka_conf_new();

	rd_kafka_conf_set(conf,"queue.buffering.max.messages", "256000",NULL,0);
	rd_kafka_conf_set(conf,"queue.buffering.max.kbytes", "1024000",NULL,0);
	rd_kafka_conf_set(conf,"queue.buffering.max.ms","20",NULL,0);
	rd_kafka_conf_set(conf,"linger.ms","20",NULL,0);

	rd_kafka_conf_set(conf,"batch.num.messages","250000",NULL,0);
	rd_kafka_conf_set(conf,"batch.size","100000000",NULL,0);


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

	int total_length = 0;
	char *locate = pac;
	int burst_size=0,i=0;


	while(1){
	if(rte_ring_empty(_kafka_ring)){
		rd_kafka_poll(rk,0);
		if(total_length!=0){
			goto retry;
		}
		continue;
	}
	struct rte_mbuf *burst_buffer[32] = { NULL };

	burst_size=rte_ring_dequeue_burst(_kafka_ring,(void *)burst_buffer,32,NULL);


	for(i=0;i<burst_size;){
		buf = rte_pktmbuf_mtod(burst_buffer[i], char *);
        int len = rte_pktmbuf_pkt_len(burst_buffer[i]);

		//添加时间戳、报文长度
		memcpy(locate,&(burst_buffer[i]->timestamp),8);
	
		locate+=8;
		total_length+=8;
		
		memcpy(locate,&len,4);
		
		locate+=4;
		total_length+=4;
        memcpy(locate,buf,len);
		locate+=len;
       
        rte_pktmbuf_free(burst_buffer[i]);
        total_length+=len;
        i++;

		//累计数据到40KB才进行入队操作
    	if(total_length<=40960){
    		continue;
     	}
	retry:
            err = rd_kafka_producev(    
                    rk,                 
                    RD_KAFKA_V_TOPIC(topic),                       
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),			
                    RD_KAFKA_V_VALUE(pac, total_length),
                	RD_KAFKA_V_PARTITION(coreid%partition),		     	
                    RD_KAFKA_V_OPAQUE(NULL),                       
                    RD_KAFKA_V_END);

		if(err){
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

    /* Destroy the producer instance */
    rd_kafka_destroy(rk);
	return;
}


//大象流识别用的数据结构
struct _flow{
	unsigned int addr;	//源ip地址
	int type;			//流位于lru1还是lru2中
	long rss;
	long len;			//累计数据量
	struct _flow *prev;	//前一个flow
	struct _flow *next; //后一个flow
	struct _list *toList;//对应的list记录
};

struct _list{
	struct _list *prev;	//前一个list
	struct _list *next;	//后一个list
	struct _flow *toFlow;	//对于的flow记录
};

//生成一个f对应的list节点，添加在tail之后，返回该节点
static struct _list* addToLru(struct _flow* f, struct _list* tail) {
	tail->toFlow = f;
	f->toList = tail;
	struct _list* q = (struct _list*)malloc(sizeof(struct _list));
	q->prev = tail;
	tail->next = q;
	tail = q;
	return tail;
}

//将f对应的list节点移到tail之后，返回该节点
static struct _list* updateLru(struct _flow* f, struct _list* tail) {
	struct _list* l = f->toList;

	if (l->next == tail) {
		return tail;
	}

	if (l->prev != NULL) {
		l->prev->next = l->next;
		l->next->prev = l->prev;
	}
	else {
		l->next->prev = NULL;
	}
	l->next = tail;
	tail->prev->next = l;
	l->prev = tail->prev;
	tail->prev = l;

	return tail;
}

//删除head及其对应的flow节点
static struct _list* removeLru(struct _list* head){
	struct _list* q = head->next;
	struct _flow* f = head->toFlow;

	if(f->next == NULL){
		f->prev->next = NULL;
	}
	else{
		f->prev->next = f->next;	
		f->next->prev = f->prev;
	}
	
	free(head->toFlow);
		
	q->prev = head->prev;
	free(head);
	head = q;
	return head;
}

//将f对应的list节点从LRU1移动到LRU2尾部
static void addToQ2(struct _flow* f, struct _list* tail){
	struct _list* q = f->toList;
	q->prev->next = q->next;
	q->next->prev = q->prev;

	q->next = tail;
	q->prev = tail->prev;
	q->prev->next = q;
	tail->prev = q;
}

//大象流识别模块
static void lcore_lru(void){
	struct rte_ring *_mbuf_ring,*_lru_ring;
	int _id = rte_lcore_id();
	int pipe = global_conf.pipeline_num;
	_mbuf_ring = global_conf.mbuf_ring[_id%pipe];
	_lru_ring =  global_conf.lru_ring[_id%pipe];
	struct rte_mbuf *bufs[32] = { NULL };
	int nb_rx,i;
	int pac_get=0;
	if(!global_conf.enable_lru){
		while(1){
			nb_rx=rte_ring_dequeue_burst(_lru_ring,(void *)bufs,32,NULL);
			rte_ring_enqueue_burst(_mbuf_ring,(void *)bufs,nb_rx,NULL);
		}
	}
	printf("core %d lru\n",_id);

	const int lru_max = 20000;	//存储流记录的数量
    const int lru_max1 = 500;	//存储大象流的最大数量
    const int lru_trigger = 1024*1024;	//大象流阈值
    const int hash_list_size = 20001;	//hash表长度
    const int hash_list_len = 4;		//hash表每个桶链表最大长度
    int list_len;
    int lru_size = 0;
    int lru_size1 = 0;
    int lru_update = 0;
    int lru_remove = 0;

	//初始化hash表
	struct _flow *ff[hash_list_size];
	struct _list* head = (struct _list*)malloc(sizeof(struct _list));
	struct _list* tail = (struct _list*)malloc(sizeof(struct _list));
	head->next = tail;
	tail->prev = head;

	struct _list* head1 = (struct _list*)malloc(sizeof(struct _list));
	struct _list* tail1 = (struct _list*)malloc(sizeof(struct _list));
	head1->next = tail1;
	tail1->prev = head1;
	
	for(i=0;i<hash_list_size;i++){
		ff[i] = (struct _flow*)malloc(sizeof(struct _flow));
		ff[i]->next = NULL;
		ff[i]->prev = NULL;
	}

	struct rte_ipv4_hdr *ipv4_hdr;
	
	while(1){
		list_len=0;
		nb_rx=rte_ring_dequeue_burst(_lru_ring,(void *)bufs,32,NULL);
		pac_get+=nb_rx;
		if(nb_rx == 0){
			continue;
		}		
		for(i=0;i<nb_rx;i++){
			int hash = bufs[i]->hash.rss%hash_list_size;
			int len = rte_pktmbuf_pkt_len(bufs[i]);

			if (RTE_ETH_IS_IPV4_HDR(bufs[i]->packet_type)){
				ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
			}
			else{
				goto end;
			}
			if(ff[hash]->next==NULL){
				struct _flow *f;
				f = (struct _flow*)malloc(sizeof(struct _flow));
				f->addr = ipv4_hdr->src_addr;
				f->type=1;      //node in lru1
				f->rss = bufs[i]->hash.rss;
				f->len=len;
				f->next = NULL;
				ff[hash]->next = f;
				f->prev = ff[hash];
				if(lru_size < lru_max){
					lru_size++;	
					tail = addToLru(f,tail);
				}
				else{
					lru_remove++;
					head->next = removeLru(head->next);
					tail = addToLru(f,tail);
				}
			}
			else{
				struct _flow *fff;
				struct _flow *p;
				fff = p = ff[hash]->next;

				while(1){
					if(ipv4_hdr->src_addr == p->addr&& p->rss == bufs[i]->hash.rss){
						p->len+=len;
						if(p->len > lru_trigger){
							if(p->type==1){
								p->type = 2;
								printf("elephent flow(rss:%d,s_ip:%d,d_ip:%d)\n)",p->rss,ipv4_hdr->src_addr,ipv4_hdr->dst_addr);
								if(lru_size1>=lru_max1){
									head1->next = removeLru(head1->next);
									addToQ2(p,tail1);
								}
								else{
									lru_size1++;
									addToQ2(p,tail1);
								}
								lru_size--;
							}
						}
						else{
							lru_update++;
							if(p->type==1){
								tail = updateLru(p,tail);
							}
							else{
								tail1 = updateLru(p,tail1);
							}
						}
						goto end;
					}
					if(p->next == NULL){
						break;
					}
					p = p->next;
					
					if(p->len < fff->len){
						fff = p;
					}
					list_len++;
					if(list_len > hash_list_len){
						if(fff->type==2){
							goto end;
						}
						fff->addr=ipv4_hdr->src_addr;
						fff->len=len;
						fff->type=1;
						fff->rss = bufs[i]->hash.rss;
						tail = updateLru(fff,tail);
						goto end;
					}
				}								
				fff = (struct _flow*)malloc(sizeof(struct _flow));
				fff->addr=ipv4_hdr->src_addr;
				fff->len=len;
				fff->type=1;
				fff->rss = bufs[i]->hash.rss;
				fff->next=NULL;
				fff->prev = p;
				p->next = fff;	
				if(lru_size < lru_max){
					lru_size++;
					tail = addToLru(fff,tail);
				}
				else{
					head->next = removeLru(head->next);
					lru_remove++;
					tail = addToLru(fff,tail);
				}									
			}
end:			continue;
		}
		rte_ring_enqueue_burst(_mbuf_ring,(void *)bufs,nb_rx,NULL);
	}
}

//流量过滤模块
static void lcore_acl(void)
{
	struct acl_search_t acl_search;
	int i,_id,pipe;
	struct rte_ring *_mbuf_ring;

	_id = rte_lcore_id();
	pipe = global_conf.pipeline_num;
	printf("core %d acl\n",_id);
	_mbuf_ring =(struct rte_ring *) global_conf.mbuf_ring[_id%pipe];

	struct rte_mbuf *bufs[32] = { NULL };
	int nb_rx;
	int pac_get=0;
	int pac_acl=0;
	int pac_free=0;

	time_t lt0,lt;
	lt0 = time(&lt0);
	
	while(1){
		nb_rx=rte_ring_dequeue_burst(_mbuf_ring,(void *)bufs,32,NULL);

		//每10秒输出一次信息
		lt = time(&lt);
		if(lt-lt0 > 10){
    		printf("core %d get %d and acled %d freed %d\n",_id,pac_get,pac_acl,pac_free);
			lt0 = lt;
		}
		
		if(nb_rx == 0){
			continue;
		}

		prepare_acl_parameter(bufs, &acl_search, nb_rx);
					
		rte_acl_classify_alg(
        		acx,
        		acl_search.data_ipv4,
        	    acl_search.res_ipv4,
        	    acl_search.num_ipv4,
        	    1,
        	    RTE_ACL_CLASSIFY_SCALAR);

		int choice;
		int j;
		
		for(i=0;i<acl_search.num_ipv4;i++){
			//choice = acl_search.m_ipv4[i]->hash.rss % 10007 % global_conf.partition_use;
			choice = pac_acl % global_conf.partition_use;
			
			acl_search.m_ipv4[i]->udata64 = 0;
			for(j=0;j<global_conf.CATEGORIES;j++){//多个类别的规则分别处理
				if(acl_search.res_ipv4[i*global_conf.CATEGORIES+j]==0){//未能匹配
					rte_pktmbuf_free(acl_search.m_ipv4[i]);
					pac_free++;
					continue;
				}
				
			    pac_acl++;
			    acl_search.m_ipv4[i]->udata64++;
			    rte_ring_enqueue(global_conf.kafka_ring[(_id % pipe)*global_conf.partition_use + choice],(void*)acl_search.m_ipv4[i]);	
		    }
		}
		pac_get+=nb_rx;
	}
}


//流量捕获模块
static void
lcore_main(void)
{

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


    rte_eth_stats_reset(0);
    int coreid = rte_lcore_id();
    struct rte_ring *_lru_ring = global_conf.lru_ring[coreid];


    printf("\nCore %u receiving packets and pass to lru_ring\n",rte_lcore_id());
    /* Run until the application is quit or killed. */

	int i;
    while(true) {
        struct rte_mbuf *bufs[BURST_SIZE];

        const uint16_t nb_rx = rte_eth_rx_burst(0, coreid,
                bufs, BURST_SIZE);
        if (unlikely(nb_rx == 0))
            continue;
            
        for(i=0;i<nb_rx;i++){
        	bufs[i]->timestamp = rte_rdtsc();//添加时间戳
//         	rte_ring_enqueue(_lru_ring,bufs[i]);
        }
    	rte_ring_enqueue_burst(_lru_ring,(void *)bufs,nb_rx,NULL);    	  
    }
}

//解析过滤规则
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

static void catnum2string(int num,char* res){
	int i=strlen(res);
	if(num >= 10){
		res[i++] = ('0'+ num/10);
		num = num % 10;
	}
	res[i++] = ('0'+num);
	res[i] = '\0';
}

//读取配置信息
static void
parse_conf(void){
	FILE *conf = fopen("config.txt","r");
	char arg[20];
	int arg_num;
	global_conf.enable_lru = 1;
	global_conf.pac_size_to_catch = 25000000;
	while(fscanf(conf,"%s %d\n",arg,&arg_num)!=EOF){
		if(strcmp(arg,"pac_size_to_catch") == 0){
			global_conf.pac_size_to_catch = arg_num;	
		}
		else if(strcmp(arg,"pipeline_num") == 0){
			global_conf.pipeline_num = arg_num;	
		}
		else if(strcmp(arg,"partition_use") == 0){
			global_conf.partition_use = arg_num;	
		}
		else if(strcmp(arg,"enable_lru") == 0){
			global_conf.enable_lru = arg_num;	
		}
		else{
			printf("please check config\n");
		}
	}
	
	global_conf.CATEGORIES = 1;

    int i;
    const char ringName[20] = "kafka_ring";
    const char mbufName[20] = "mbuf_ring";
    const char lruName[20] = "lru_ring";
    char NameT[20];
   
    for(i=0;i<global_conf.pipeline_num * global_conf.partition_use;i++){
    		strcpy(NameT,ringName);
    		catnum2string(i,NameT);
    		global_conf.kafka_ring[i] = rte_ring_create(NameT, 65536, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    		printf("%s\n",NameT);
    }
    for(i=0;i<global_conf.pipeline_num;i++){
    		strcpy(NameT,mbufName);
    		catnum2string(i,NameT);
    		global_conf.mbuf_ring[i] = rte_ring_create(NameT, 65536, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    		printf("%s\n",NameT);
    }
    for(i=0;i<global_conf.pipeline_num;i++){
    		strcpy(NameT,lruName);
    		catnum2string(i,NameT);
    		global_conf.lru_ring[i] = rte_ring_create(NameT, 65536, rte_socket_id(), RING_F_SP_ENQ| RING_F_SC_DEQ);
    		printf("%s\n",NameT);
    }
}

//初始化环境，启动各个模块
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
    
    parse_conf();
    nb_ports = rte_eth_dev_count_avail();
    printf("%d ports find\n",nb_ports);
    
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
	global_conf.rule_number = ipv4_5_tuple_parse();
	ret = rte_acl_add_rules(acx, (const struct rte_acl_rule *)acl_rules, global_conf.rule_number);
	if (ret != 0) {
		printf("err in acl rules");
	/* handle error at adding ACL rules. */
	}

	/* prepare AC build config. */

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
	int pipe = global_conf.pipeline_num;
	for(i=pipe;i<pipe*2;i++) // core pipe to 2pipe
		rte_eal_remote_launch((lcore_function_t*)lcore_lru,NULL,i);
	
	for(i=pipe*2;i<pipe*3;i++) //core 2pipe to 3pipe	
		rte_eal_remote_launch((lcore_function_t*)lcore_acl,NULL,i);
	
	for(i=pipe*3;i<(pipe*3+pipe*global_conf.partition_use);i++){//core 3pipe to 3pipe+pipe*partition_num
		rte_eal_remote_launch((lcore_function_t*)lcore_kafka,NULL,i);
	}
	rte_eal_remote_launch((lcore_function_t*)lcore_info,NULL,i);
	for(i=1;i<pipe;i++) //core 0 to pipe
		rte_eal_remote_launch((lcore_function_t*)lcore_main,NULL,i);
	lcore_main();
	return 0;
}
