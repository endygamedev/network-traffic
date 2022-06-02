#pragma once

void ethernet_header(unsigned char *buffer);
void ip_header(unsigned char *buffer);
void payload(unsigned char *buffer, int buflen);
void tcp_header(unsigned char *buffer, int buflen);
void udp_header(unsigned char *buffer, int buflen);
void data_process(unsigned char *buffer, int buflen);
