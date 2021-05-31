# 高通量网络流量过滤与存储工具	

## Summary

​	基于dpdk和Kakfa，支持在10Gbps链路上进行流量捕获、在线过滤和存储

​	使用了流水线架构，适用于多核服务器(至少4个核心)

## Requirements

​	dpdk-20.08，http://fast.dpdk.org/rel/dpdk-20.08.tar.xz

​	kafka 2.1.2

​	zookeeper 3.4.14

​	librdkafka 1.7.0

## Configuration

​	配置zookeeper，创建Kafka集群，创建topic，设置分区为4

​	编译dpdk、librdkafka

​	编译本工具

## Usage

​	sudo ./build/conf  -c 1 -n 4	根据链路状况自动配置部分重要参数

​	根据需要配置rules.txt文件和conf.txt文件

​	sudo ./build/acl_save  -c （核心使用） -n 4	运行流量过滤与存储工具

​	sudo ./consumer (broker) (group.id) (topic) [partition]	消费topic，生成pcap文件