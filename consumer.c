#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>


/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
//#include <librdkafka/rdkafka.h>
#include "rdkafka.h"
 
//pcap文件数据结构
typedef unsigned int  bpf_u_int32;  
typedef unsigned short  u_short;  
typedef int bpf_int32;  
         
typedef struct pcap_file_header {  
    bpf_u_int32 magic;  
    u_short major;  
    u_short minor;  
    bpf_int32 thiszone;      
    bpf_u_int32 sigfigs;     
    bpf_u_int32 snaplen;     
    bpf_u_int32 linktype;    
}pcap_file_header;  
       
       
typedef struct  timestamp{  
    bpf_u_int32 timestamp_s;  
    bpf_u_int32 timestamp_ms;  
}timestamp;  
       
typedef struct pcap_header{  
    timestamp ts;  
    bpf_u_int32 capture_len;  
    bpf_u_int32 len;  
       
}pcap_header;  

//写pcap文件头部
void write_file_header(FILE *fd , pcap_file_header * pcap_file_hdr)
{
    fwrite(pcap_file_hdr,sizeof(pcap_file_header),1,fd);
}
 
void write_header(FILE *fd ,pcap_header * pcap_hdr)
{
    fwrite(pcap_hdr,sizeof(pcap_header),1,fd);
    
}

//中断
static volatile sig_atomic_t run = 1;

/**
 * @brief Signal termination of program
 */
static void stop (int sig) {
        run = 0;
}


int main (int argc, char **argv) {
    rd_kafka_t *rk;          /* Consumer instance handle */
    rd_kafka_conf_t *conf;   /* Temporary configuration object */
    rd_kafka_resp_err_t err; /* librdkafka API error code */
    char errstr[512];        /* librdkafka API error reporting buffer */
    const char *brokers;     /* Argument: broker list */
    const char *groupid;     /* Argument: Consumer group id */
    char **topics;           /* Argument: list of topics to subscribe to */
    rd_kafka_topic_partition_list_t *subscription; /* Subscribed topics */
    
    FILE *fd;

    //参数检查
    if (argc < 4) {
            fprintf(stderr,
                    "%% Usage: "
                    "%s<broker.id> <group.id> <topic.id> [partition.id]..\n",
                    argv[0]);
            return 1;
    }

    brokers   = argv[1];
    groupid   = argv[2];
    topics    = &argv[3];
    
    //根据参数生成文件名
    char filename[30] = "pcap/";
    strcat(filename,topics[0]);
    if(argc == 5){
            strcat(filename,"_");
            strcat(filename,topics[1]);
    }
    strcat(filename,".pcap");
    fd = fopen(filename,"wb+");
    
    //创建和设置环境
    conf = rd_kafka_conf_new();

  
    if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
                            errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
            fprintf(stderr, "%s\n", errstr);
            rd_kafka_conf_destroy(conf);
            return 1;
    }

    if (rd_kafka_conf_set(conf, "group.id", groupid,
                            errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
            fprintf(stderr, "%s\n", errstr);
            rd_kafka_conf_destroy(conf);
            return 1;
    }

    if (rd_kafka_conf_set(conf, "auto.offset.reset", "earliest",
                            errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
            fprintf(stderr, "%s\n", errstr);
            rd_kafka_conf_destroy(conf);
            return 1;
    }


    rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!rk) {
            fprintf(stderr,
                    "%% Failed to create new consumer: %s\n", errstr);
            return 1;
    }

    conf = NULL; /* Configuration object is now owned, and freed,
                    * by the rd_kafka_t instance. */


    rd_kafka_poll_set_consumer(rk);


    /* Convert the list of topics to a format suitable for librdkafka */
    subscription = rd_kafka_topic_partition_list_new(1);

    //根据参数设置 订阅、指定消费两种模式
    if(argc == 4){
        rd_kafka_topic_partition_list_add(subscription,
                                        topics[0],
                                        /* the partition is ignored
                                            * by subscribe() */
                                        RD_KAFKA_PARTITION_UA);

        /* Subscribe to the list of topics */
    
        err = rd_kafka_subscribe(rk, subscription);
    }
    else if(argc == 5){
        rd_kafka_topic_partition_list_add(subscription,
                                                topics[0],
                                                topics[1][0] - '0');
        err = rd_kafka_assign(rk, subscription);                                       
    }

    else{
        printf("please check your input\n");
        return -1;
    }
                

 
    if (err) {
        fprintf(stderr,
                "%% Failed to subscribe/assign to %d topics: %s\n",
                subscription->cnt, rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(subscription);
        rd_kafka_destroy(rk);
        return 1;
    }

    fprintf(stderr,
            "%% Subscribed/assigned to %d topic(s), "
            "waiting for rebalance and messages...\n",
            subscription->cnt);

    rd_kafka_topic_partition_list_destroy(subscription);


    /* Signal handler for clean shutdown */
    signal(SIGINT, stop);

    //填充pcap文件头部信息
	pcap_file_header pcap_file_hdr;
	timestamp pcap_timemp;
    pcap_header pcap_hdr;
    

    pcap_file_hdr.magic = 0xa1b2c3d4;
    pcap_file_hdr.major = 2;
    pcap_file_hdr.minor = 4;
    pcap_file_hdr.thiszone = 0;
    pcap_file_hdr.sigfigs  = 0;
    pcap_file_hdr.snaplen  = 65535;
    pcap_file_hdr.linktype =1;

    pcap_timemp.timestamp_s = 0;
    pcap_timemp.timestamp_ms= 0;
    write_file_header(fd,&pcap_file_hdr);


	int receive_num = 0;
    while (run) {
        rd_kafka_message_t *rkm;
        //从集群拉取消息
        rkm = rd_kafka_consumer_poll(rk, 10);
        if (!rkm)
                continue; /* Timeout: no message within 100ms,
                            *  try again. This short timeout allows
                            *  checking for `run` at frequent intervals.
                            */

        /* consumer_poll() will return either a proper message
            * or a consumer error (rkm->err is set). */
        if (rkm->err) {
                /* Consumer errors are generally to be considered
                    * informational as the consumer will automatically
                    * try to recover from all types of errors. */
                fprintf(stderr,
                        "%% Consumer error: %s\n",
                        rd_kafka_message_errstr(rkm));
                rd_kafka_message_destroy(rkm);
                continue;
        }
        if(!(int)rkm->len){
            rd_kafka_message_destroy(rkm);	
            continue;
        }
        //将消息填充到pcap文件中
        char* locate = rkm->payload;
        u_int32_t offset = 0;
        bpf_u_int32 msec = 0;
        while(offset < (u_int32_t)rkm->len){  
            long long tick = *(long long*)(locate+offset);
            offset+=8;
            pcap_timemp.timestamp_s = tick/(1000*1000*1000);

            msec = tick/1000 - pcap_timemp.timestamp_s*1000*1000;
            
            pcap_timemp.timestamp_ms = msec;
            
            int packet_len = *(int*)(locate + offset);
            offset += 4;
            pcap_hdr.capture_len = packet_len;
            pcap_hdr.len = packet_len;;
            pcap_hdr.ts = pcap_timemp;    

            fseek(fd,0,SEEK_END);
            write_header(fd,&pcap_hdr);
            fseek(fd,0,SEEK_END);
            fwrite(locate+offset,packet_len,1,fd);
            offset+=packet_len;

            receive_num++;
            if(receive_num%100000==0){
                printf("%d packets\n",receive_num);
            }
        }
        rd_kafka_message_destroy(rkm);
    }
    printf("%d packets saved",receive_num);
    /* Close the consumer: commit final offsets and leave the group. */
    fprintf(stderr, "%% Closing consumer\n");
    fclose(fd);
    printf("file closed\n");
    rd_kafka_consumer_close(rk);
    /* Destroy the consumer */
    rd_kafka_destroy(rk);
    printf("consumer destroyed\n");
    return 0;
}



