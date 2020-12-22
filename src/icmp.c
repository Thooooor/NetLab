#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查buf长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // 检查长度
    icmp_hdr_t *icmp_header = (icmp_hdr_t *)buf->data;
    // 校验和
    uint16_t temp_checksum = icmp_header->checksum;
    icmp_header->checksum = 0;
    uint16_t checksum = checksum16((uint16_t *)icmp_header, buf->len);
    icmp_header->checksum = temp_checksum;
    if (checksum != temp_checksum) return;
    
    // 是否为回显请求
    if (icmp_header->type == ICMP_TYPE_ECHO_REQUEST)
    {
        // 初始化buf
        buf_init(&txbuf, buf->len);
        // 拷贝数据
        for (int i = 0; i < buf->len; i++) txbuf.data[i] = buf->data[i];
        // 填写报头
        icmp_hdr_t *reply_header = (icmp_hdr_t *)txbuf.data;
        reply_header->type = ICMP_TYPE_ECHO_REPLY;
        reply_header->code = ICMP_CODE_ECHO_REQUEST;
        reply_header->id = icmp_header->id;
        reply_header->seq = icmp_header->seq;
        reply_header->checksum = 0;
        reply_header->checksum = checksum16((uint16_t *)reply_header, txbuf.len);
        // 发送
        ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
    }
}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // 初始化buf
    int buf_length = sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, buf_length);
    // 填写报头首部
    icmp_hdr_t *header = (icmp_hdr_t *)txbuf.data;
    header->type = ICMP_TYPE_UNREACH;
    header->code = code;
    header->id = 0;
    header->seq = 0;
    header->checksum = 0;
    // 未用的部分为0
    for (int i = 0; i < sizeof(ip_hdr_t) + 8; i++) txbuf.data[i+sizeof(icmp_hdr_t)] = recv_buf->data[i];
    // 校验和
    header->checksum = checksum16((uint16_t *)header, txbuf.len);
    //发送
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}