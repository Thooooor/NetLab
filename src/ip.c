#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>

int id = 0;

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    ip_hdr_t *ip_header = (ip_hdr_t *)buf->data;
    // 报头检查
    if (
        ip_header->version != IP_VERSION_4
        || ip_header->hdr_len * IP_HDR_LEN_PER_BYTE != sizeof(ip_hdr_t)
        || ip_header->total_len < sizeof(ip_hdr_t)
        ) return;

    // 检验和
    uint16_t temp_checksum = ip_header->hdr_checksum;
    ip_header->hdr_checksum = 0;
    uint16_t checksum = checksum16((uint16_t *)ip_header, sizeof(ip_hdr_t));
    ip_header->hdr_checksum = temp_checksum;
    if (checksum != temp_checksum) return;

    // 检查IP地址
    for (int i = 0; i < NET_IP_LEN; i++) if (ip_header->dest_ip[i] != net_if_ip[i]) return;

    // 检查IP报头的协议字段
    switch (ip_header->protocol) {
        case NET_PROTOCOL_ICMP:
            buf_remove_header(buf, sizeof(ip_hdr_t));
            icmp_in(buf, ip_header->src_ip);
            break;
        case NET_PROTOCOL_UDP:
            buf_remove_header(buf, sizeof(ip_hdr_t));
            udp_in(buf, ip_header->src_ip);
            break;
        default:
            icmp_unreachable(buf, ip_header->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            break;
    }
}

/**
 * @brief 处理一个要发送的分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 增加头部空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *header = (ip_hdr_t *)buf->data;
    // 填写头部字段
    header->version = IP_VERSION_4;
    header->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    header->tos = 0;
    header->total_len = swap16(buf->len);
    header->id = swap16(id);
    // 位偏移
    if (mf) header->flags_fragment = IP_MORE_FRAGMENT | swap16(offset);
    else header->flags_fragment = 0 | swap16(offset);
    header->ttl = IP_DEFALUT_TTL;
    header->protocol = protocol;
    // IP地址
    for (int i = 0; i < NET_IP_LEN; i++) header->src_ip[i] = net_if_ip[i];
    for (int i = 0; i< NET_IP_LEN; i++) header->dest_ip[i] = ip[i];
    // checksum填0，重新计算
    header->hdr_checksum = 0;
    header->hdr_checksum = checksum16((uint16_t *)header, sizeof(ip_hdr_t));

    // 发送
    arp_out(buf, ip, NET_PROTOCOL_IP);
}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - ip包头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - ip包头头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // 检查长度
    int max_length = ETHERNET_MTU - sizeof(ip_hdr_t);
    if (buf->len > max_length) { // 超过则分片发送
        // 初始化buf
        buf_t ip_buf;
        buf_t  *frag_buf = &ip_buf;
        buf_init(frag_buf, max_length);

        uint16_t left_length = buf->len;
        
        // 对于超过部分进行分片，直到不超过最大长度
        int count = 0;
        while (left_length >= max_length) {
            frag_buf->len = max_length;
            frag_buf->data = buf->data;
            ip_fragment_out(frag_buf, ip, protocol, id, (count * (max_length)) >> 3, 1);
            buf->data += max_length;
            left_length -= max_length;
            count++;
        }
        // 对剩余部分进行发送
        if (left_length > 0) {
            buf_init(frag_buf, left_length);
            frag_buf->len = left_length;
            frag_buf->data = buf->data;
            ip_fragment_out(frag_buf, ip, protocol, id, (count * (max_length)) >> 3, 0);
        }
    }
    else ip_fragment_out(buf, ip, protocol, id, 0, 0);
    id++;
}
