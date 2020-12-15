#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

#define HEADLENGTH 14
#define IP 0
#define ARP 6
/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    char *ethernet_head = buf->data;
    unsigned char *p = ethernet_head;
    if (p[12] == 8) {
        switch (p[13])
        {
            case IP:
                buf_remove_header(buf, HEADLENGTH);
                ip_in(buf);
                break;
            case ARP:
                buf_remove_header(buf, HEADLENGTH);
                arp_in(buf);
                break;
            default: 
                break;
        }
    }
    
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标mac地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    buf_add_header(buf, HEADLENGTH);
    char *ethernet_head = buf->data;
    unsigned char *p = ethernet_head;
    for (int i = 0; i < 6; i++) {
        p[i] = mac[i];
    }
    p = ethernet_head + 6;
    p[0] = 0x11;
    p[1] = 0x22;
    p[2] = 0x33;
    p[3] = 0x44;
    p[4] = 0x55;
    p[5] = 0x66;
    p[6] = (protocol&0xFF00)>>8;
    p[7] = (protocol&0x00FF);
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
