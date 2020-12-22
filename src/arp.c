#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{
    // 轮询是否有超时
    for (int i = 0; i < ARP_MAX_ENTRY; i++) {
        if (time(NULL) - arp_table[i].timeout > ARP_TIMEOUT_SEC) {
            arp_table[i].state = ARP_INVALID;
        }
    }
    // 是否有无效表项
    for (int i = 0; i < ARP_MAX_ENTRY; i++) {
        if (arp_table[i].state == ARP_INVALID) {
            for (int j = 0; j < NET_MAC_LEN; j++) arp_table[i].mac[j] = mac[j];
            for (int j = 0; j < NET_IP_LEN; j++) arp_table[i].ip[j] = ip[j];
            arp_table[i].state = state;
            arp_table[i].timeout = time(NULL) + ARP_TIMEOUT_SEC;
            return;
        }
    }
    // 查找超时时间最长的一条表项
    int index = 0;
    int longest = arp_table[0].timeout;
    for (int i = 1; i < ARP_MAX_ENTRY; i++) {
        if (arp_table[i].timeout < longest) {
            longest = arp_table[i].timeout;
            index = i;
        }
    }
    arp_table[index].state = state;
    arp_table[index].timeout = time(NULL) + ARP_TIMEOUT_SEC;
    for (int j = 0; j < NET_MAC_LEN; j++) arp_table[index].mac[j] = mac[j];
    for (int j = 0; j < NET_IP_LEN; j++) arp_table[index].ip[j] = ip[j];
}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
static void arp_req(uint8_t *target_ip)
{
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // 初始化header
    arp_pkt_t *header = (arp_pkt_t *)txbuf.data;
    *header = arp_init_pkt;
    header->opcode = swap16(ARP_REQUEST);
    for (int i = 0; i < NET_IP_LEN; i++) header->target_ip[i] = target_ip[i];
    // 发送
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)
{
    arp_pkt_t *header = (arp_pkt_t *)buf->data;
    int opcode = swap16(header->opcode);
    if (header->hw_type != swap16(ARP_HW_ETHER)
        || header->pro_type != swap16(NET_PROTOCOL_IP)
        || header->hw_len != NET_MAC_LEN
        || header->pro_len != NET_IP_LEN
        || (opcode != ARP_REQUEST && opcode != ARP_REPLY)
    ) return;

    arp_update(header->sender_ip, header->sender_mac, ARP_VALID);

    if (arp_buf.valid){
        uint8_t *target_mac;
        target_mac = arp_lookup(header->sender_ip);
        if (target_mac == NULL) return;
        arp_buf.valid = 0;
        ethernet_out(&(arp_buf.buf), target_mac, arp_buf.protocol);
    } else {
        if (opcode != ARP_REQUEST) return;
        for (int i = 0; i < NET_IP_LEN; i++) {
            if (header->target_ip[i] != net_if_ip[i]) return;
        }

        buf_init(&txbuf, sizeof(arp_pkt_t));
        arp_pkt_t *sender = (arp_pkt_t *)txbuf.data;
        *sender = arp_init_pkt;
        sender->opcode = swap16(ARP_REPLY);
        for (int i = 0; i < NET_IP_LEN; i++) sender->target_ip[i] = header->sender_ip[i];
        for (int i = 0; i < NET_MAC_LEN; i++) sender->target_mac[i] = header->sender_mac[i];
        ethernet_out(&txbuf, sender->target_mac, NET_PROTOCOL_ARP);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    uint8_t *mac = arp_lookup(ip);

    if (mac != NULL) {
        ethernet_out(buf, mac, protocol);
    } else {
        arp_req(ip);
        arp_buf.buf = *buf;
        for (int i = 0; i < NET_IP_LEN; i++) arp_buf.ip[i] = ip[i];
        arp_buf.protocol = protocol;
        arp_buf.valid = 1;
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;
    arp_req(net_if_ip);
}
