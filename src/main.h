#pragma once

void packet_information(unsigned char *buffer);
void data_process(unsigned char *buffer);
int is_number(char *arg);
int check_ip_record(char *ip);
int check_port(int port);
