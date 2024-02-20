#include "hw1.h"
#include <stdio.h>
#include <stdlib.h>

void print_packet_sf(unsigned char packet[])
{
    unsigned int source_address = (packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
    source_address >>=4;
    printf("Source Address: %u\n", source_address);

    unsigned int destination_address = (packet[3] << 24) | (packet[4] << 16) | (packet[5] << 8) | packet[6];
    destination_address &= ~(1<<31);
    destination_address &= ~(1<<30);
    destination_address &= ~(1<<29);
    destination_address &= ~(1<<28);
    printf("Destination Address: %u\n", destination_address);

    unsigned int source_port = (packet[7] & 0xF0) >> 4;
    printf("Source Port: %u\n", source_port);

    unsigned int destination_port = packet[7] & 0x0F;
    printf("Destination Port: %u\n", destination_port);

    unsigned int fragment_offset = (packet[8] << 8) | packet[9];
    fragment_offset >>=2;
    printf("Fragment Offset: %u\n", fragment_offset);

    unsigned int packet_length = (packet[9] << 16) | (packet[10] << 8) | packet[11];
    packet_length >>=4;
    packet_length &= ~(1<<23);
    packet_length &= ~(1<<22);
    packet_length &= ~(1<<21);
    packet_length &= ~(1<<20);
    packet_length &= ~(1<<19);
    packet_length &= ~(1<<18);
    packet_length &= ~(1<<17);
    packet_length &= ~(1<<16);
    packet_length &= ~(1<<15);
    packet_length &= ~(1<<14);
    printf("Packet Length: %u\n", packet_length);

    unsigned int max_hop_count = (packet[11] << 8) | packet[12];
    max_hop_count >>=7;
    max_hop_count &= ~(1<<15);
    max_hop_count &= ~(1<<14);
    max_hop_count &= ~(1<<13);
    max_hop_count &= ~(1<<12);
    max_hop_count &= ~(1<<11);
    max_hop_count &= ~(1<<10);
    max_hop_count &= ~(1<<11);
    max_hop_count &= ~(1<<10);
    max_hop_count &= ~(1<<9);
    max_hop_count &= ~(1<<8);
    max_hop_count &= ~(1<<7);
    printf("Maximum Hop Count: %u\n", max_hop_count);
    

    unsigned int checksum = (packet[12] << 16) | (packet[13] << 8) | packet[14];
    checksum &= ~(1<<23);
    printf("Checksum: %u\n", checksum);

    unsigned int compression_scheme = packet[15];
    compression_scheme >>=6;
    printf("Compression Scheme: %u\n", compression_scheme);

    unsigned int traffic_class = packet[15];
    traffic_class &= ~(1<<7);
    traffic_class &= ~(1<<6);
    printf("Traffic Class: %u\n", traffic_class);

    
    printf("Payload:");
    for (int i = 16; i<packet_length; i+=4){
        int payload_part = (packet[i] << 24) |  (packet[i+1] << 16) | (packet[i+2] << 8) | packet[i+3];
        printf(" %d", payload_part);
    }
    printf("\n");


}

unsigned int compute_checksum_sf(unsigned char packet[]) {
    int total_field_sum = 0;

    unsigned int source_address = (packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
    source_address >>= 4;
    total_field_sum += source_address;

    unsigned int destination_address = (packet[3] << 24) | (packet[4] << 16) | (packet[5] << 8) | packet[6];
    destination_address &= ~(1 << 31);
    destination_address &= ~(1 << 30);
    destination_address &= ~(1 << 29);
    destination_address &= ~(1 << 28);
    total_field_sum += destination_address;

    unsigned int source_port = (packet[7] & 0xF0) >> 4;
    total_field_sum += source_port;

    unsigned int destination_port = packet[7] & 0x0F;
    total_field_sum += destination_port;

    unsigned int fragment_offset = (packet[8] << 8) | packet[9];
    fragment_offset >>= 2;
    total_field_sum += fragment_offset;

    unsigned int packet_length = (packet[9] << 16) | (packet[10] << 8) | packet[11];
    packet_length >>= 4;
    packet_length &= ~((1 << 23) | (1 << 22) | (1 << 21) | (1 << 20) | (1 << 19) | (1 << 18) | (1 << 17) | (1 << 16) | (1 << 15) | (1 << 14));
    total_field_sum += packet_length;

    unsigned int max_hop_count = (packet[11] << 8) | packet[12];
    max_hop_count >>= 7;
    max_hop_count &= ~((1 << 15) | (1 << 14) | (1 << 13) | (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 7));
    total_field_sum += max_hop_count;

    unsigned int compression_scheme = packet[15];
    compression_scheme >>= 6;
    total_field_sum += compression_scheme;

    unsigned int traffic_class = packet[15];
    traffic_class &= ~((1 << 7) | (1 << 6));
    total_field_sum += traffic_class;

    total_field_sum %= ((1 << 23) - 1);

    unsigned int sum_of_payloads = 0;
    for (int i = 16; i < packet_length; i += 4) {
        int payload_part = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
        sum_of_payloads = (sum_of_payloads + abs(payload_part)) % ((1 << 23) - 1);
        
    }

    int checksum = (total_field_sum + sum_of_payloads) % ((1 << 23) - 1);
    return checksum;
}


unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    unsigned int return_num = 0;
    for (int i = 0; i<packets_len; i++){
        unsigned int fragment_offset = (packets[i][8] << 8) | packets[i][9];
        fragment_offset >>=2;
        fragment_offset /= 4;

        unsigned int checksum = (packets[i][12] << 16) | (packets[i][13] << 8) | packets[i][14];
        checksum &= ~(1<<23);

        unsigned int packet_length = (packets[i][9] << 16) | (packets[i][10] << 8) | packets[i][11];
        packet_length >>= 4;
        packet_length &= ~((1 << 23) | (1 << 22) | (1 << 21) | (1 << 20) | (1 << 19) | (1 << 18) | (1 << 17) | (1 << 16) | (1 << 15) | (1 << 14));
        

        int index_array = fragment_offset;
        
        if (checksum==compute_checksum_sf(packets[i])){
            int count = 0;
            
            for (int j = 16; j<(packet_length); j+=4){
                int payload1 = packets[i][j] << 24;
                int payload2 = packets[i][j+1] << 16;
                int payload3 = packets[i][j+2] << 8;
                int payload4 = packets[i][j+3];
                int payload_part =  (payload1 | payload2 | payload3 | payload4) ;
                if (array_len>(fragment_offset + count)){
                    array[fragment_offset + count] = payload_part;
                    return_num+=1;
                }
                count++;
                
                
            }
            
        }
        
    } 
     for (int k = 0; k<array_len; k++){
         printf("%d ", array[k]);
     }
    return return_num;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    int count_packets = 0;
    for (int i = 0; i<packets_len; i++){
        unsigned int num_bytes = 16+ max_payload;
        packets[i] = malloc(num_bytes);
        packets[i][0] = src_addr >> 20;

        packets[i][1] = src_addr >>12;
        packets[i][1] &= ~(1<<27);
        packets[i][1] &= ~(1<<26);
        packets[i][1] &= ~(1<<25);
        packets[i][1] &= ~(1<<24);
        packets[i][1] &= ~(1<<23);
        packets[i][1] &= ~(1<<22);
        packets[i][1] &= ~(1<<21);
        packets[i][1] &= ~(1<<20);
        packets[i][1] &= ~(1<<19);
        packets[i][1] &= ~(1<<18);
        packets[i][1] &= ~(1<<17);
        packets[i][1] &= ~(1<<16);
        packets[i][1] &= ~(1<<15);
        packets[i][1] &= ~(1<<14);
        packets[i][1] &= ~(1<<13);
        packets[i][1] &= ~(1<<12);
        packets[i][1] &= ~(1<<11);
        packets[i][1] &= ~(1<<10);
        packets[i][1] &= ~(1<<9);
        packets[i][1] &= ~(1<<8);

        
        packets[i][2] = src_addr>>4;
        packets[i][2] &= ~(1<<27);
        packets[i][2] &= ~(1<<26);
        packets[i][2] &= ~(1<<25);
        packets[i][2] &= ~(1<<24);
        packets[i][2] &= ~(1<<23);
        packets[i][2] &= ~(1<<22);
        packets[i][2] &= ~(1<<21);
        packets[i][2] &= ~(1<<20);
        packets[i][2] &= ~(1<<19);
        packets[i][2] &= ~(1<<18);
        packets[i][2] &= ~(1<<17);
        packets[i][2] &= ~(1<<16);
        packets[i][2] &= ~(1<<15);
        packets[i][2] &= ~(1<<14);
        packets[i][2] &= ~(1<<13);
        packets[i][2] &= ~(1<<12);
        packets[i][2] &= ~(1<<11);
        packets[i][2] &= ~(1<<10);
        packets[i][2] &= ~(1<<9);
        packets[i][2] &= ~(1<<8);

        
        packets[i][3] = src_addr;
        packets[i][3] &= ~(1<<27);
        packets[i][3] &= ~(1<<26);
        packets[i][3] &= ~(1<<25);
        packets[i][3] &= ~(1<<24);
        packets[i][3] &= ~(1<<23);
        packets[i][3] &= ~(1<<22);
        packets[i][3] &= ~(1<<21);
        packets[i][3] &= ~(1<<20);
        packets[i][3] &= ~(1<<19);
        packets[i][3] &= ~(1<<18);
        packets[i][3] &= ~(1<<17);
        packets[i][3] &= ~(1<<16);
        packets[i][3] &= ~(1<<15);
        packets[i][3] &= ~(1<<14);
        packets[i][3] &= ~(1<<13);
        packets[i][3] &= ~(1<<12);
        packets[i][3] &= ~(1<<11);
        packets[i][3] &= ~(1<<10);
        packets[i][3] &= ~(1<<9);
        packets[i][3] &= ~(1<<8);
        packets[i][3] &= ~(1<<7);
        packets[i][3] &= ~(1<<6);
        packets[i][3] &= ~(1<<5);
        packets[i][3] &= ~(1<<4);
        packets[i][3] <<= 4;
        packets[i][3] |= dest_addr>>24; // Mistake but I can't find it
        
        
        

        packets[i][4] = dest_addr>>16;
        packets[i][4] &= ~(1<<27);
        packets[i][4] &= ~(1<<26);
        packets[i][4] &= ~(1<<25);
        packets[i][4] &= ~(1<<24);
        packets[i][4] &= ~(1<<23);
        packets[i][4] &= ~(1<<22);
        packets[i][4] &= ~(1<<21);
        packets[i][4] &= ~(1<<20);
        packets[i][4] &= ~(1<<19);
        packets[i][4] &= ~(1<<18);
        packets[i][4] &= ~(1<<17);
        packets[i][4] &= ~(1<<16);
        packets[i][4] &= ~(1<<15);
        packets[i][4] &= ~(1<<14);
        packets[i][4] &= ~(1<<13);
        packets[i][4] &= ~(1<<12);
        packets[i][4] &= ~(1<<11);
        packets[i][4] &= ~(1<<10);
        packets[i][4] &= ~(1<<9);
        packets[i][4] &= ~(1<<8);

        packets[i][5] = dest_addr>>8;
        packets[i][5] &= ~(1<<27);
        packets[i][5] &= ~(1<<26);
        packets[i][5] &= ~(1<<25);
        packets[i][5] &= ~(1<<24);
        packets[i][5] &= ~(1<<23);
        packets[i][5] &= ~(1<<22);
        packets[i][5] &= ~(1<<21);
        packets[i][5] &= ~(1<<20);
        packets[i][5] &= ~(1<<19);
        packets[i][5] &= ~(1<<18);
        packets[i][5] &= ~(1<<17);
        packets[i][5] &= ~(1<<16);
        packets[i][5] &= ~(1<<15);
        packets[i][5] &= ~(1<<14);
        packets[i][5] &= ~(1<<13);
        packets[i][5] &= ~(1<<12);
        packets[i][5] &= ~(1<<11);
        packets[i][5] &= ~(1<<10);
        packets[i][5] &= ~(1<<9);
        packets[i][5] &= ~(1<<8);

        packets[i][6] = dest_addr;
        packets[i][6] &= ~(1<<27);
        packets[i][6] &= ~(1<<26);
        packets[i][6] &= ~(1<<25);
        packets[i][6] &= ~(1<<24);
        packets[i][6] &= ~(1<<23);
        packets[i][6] &= ~(1<<22);
        packets[i][6] &= ~(1<<21);
        packets[i][6] &= ~(1<<20);
        packets[i][6] &= ~(1<<19);
        packets[i][6] &= ~(1<<18);
        packets[i][6] &= ~(1<<17);
        packets[i][6] &= ~(1<<16);
        packets[i][6] &= ~(1<<15);
        packets[i][6] &= ~(1<<14);
        packets[i][6] &= ~(1<<13);
        packets[i][6] &= ~(1<<12);
        packets[i][6] &= ~(1<<11);
        packets[i][6] &= ~(1<<10);
        packets[i][6] &= ~(1<<9);
        packets[i][6] &= ~(1<<8);

        packets[i][7] = src_port<<4;
        packets[i][7] |= dest_port;

        int fragment_offset = i*max_payload;
        packets[i][8] = fragment_offset; //fragment offset
        packets[i][8] >>=6;


        packets[i][9] |= fragment_offset;
        packets[i][9] &= ~(1<<13);
        packets[i][9] &= ~(1<<12);
        packets[i][9] &= ~(1<<11);
        packets[i][9] &= ~(1<<10);
        packets[i][9] &= ~(1<<9);
        packets[i][9] &= ~(1<<8);
        packets[i][9] &= ~(1<<7);
        packets[i][9] &= ~(1<<6);
        packets[i][9] <<= 2;
        int packet_length = 16 + max_payload; // PACKET LENGTH IS HERE
        packets[i][9] |= packet_length>>12;
        


        packets[i][10] = packet_length;
        packets[i][10] >>= 4;  
        packets[i][10] &= ~(1<<13);
        packets[i][10] &= ~(1<<12);
        packets[i][10] &= ~(1<<11);
        packets[i][10] &= ~(1<<10);
        packets[i][10] &= ~(1<<9);
        packets[i][10] &= ~(1<<8);

        packets[i][11] = packet_length;
        packets[i][11] &= ~(1<<13);
        packets[i][11] &= ~(1<<12);
        packets[i][11] &= ~(1<<11);
        packets[i][11] &= ~(1<<10);
        packets[i][11] &= ~(1<<9);
        packets[i][11] &= ~(1<<8);
        packets[i][11] &= ~(1<<7);
        packets[i][11] &= ~(1<<6);
        packets[i][11] &= ~(1<<5);
        packets[i][11] &= ~(1<<4);
        packets[i][11] <<= 4;
        packets[i][11] |= maximum_hop_count>>1;
        
        

        

        packets[i][15] = compression_scheme<<6;
        packets[i][15] |= traffic_class;


        //PAYLOAD PART
        int packet_index = 16;
        for (int j = fragment_offset; j<fragment_offset+max_payload && j<array_len; j++){
            int payload_num = array[j];
            packets[i][packet_index] = payload_num>>24;

            packets[i][packet_index+1] = payload_num>>16;
            packets[i][packet_index+1] &= ~(1<<31);
            packets[i][packet_index+1] &= ~(1<<30);
            packets[i][packet_index+1] &= ~(1<<29);
            packets[i][packet_index+1] &= ~(1<<28);
            packets[i][packet_index+1] &= ~(1<<27);
            packets[i][packet_index+1] &= ~(1<<26);
            packets[i][packet_index+1] &= ~(1<<25);
            packets[i][packet_index+1] &= ~(1<<24);
            packets[i][packet_index+1] &= ~(1<<23);
            packets[i][packet_index+1] &= ~(1<<22);
            packets[i][packet_index+1] &= ~(1<<21);
            packets[i][packet_index+1] &= ~(1<<20);
            packets[i][packet_index+1] &= ~(1<<19);
            packets[i][packet_index+1] &= ~(1<<18);
            packets[i][packet_index+1] &= ~(1<<17);
            packets[i][packet_index+1] &= ~(1<<16);
            packets[i][packet_index+1] &= ~(1<<15);
            packets[i][packet_index+1] &= ~(1<<14);
            packets[i][packet_index+1] &= ~(1<<13);
            packets[i][packet_index+1] &= ~(1<<12);
            packets[i][packet_index+1] &= ~(1<<11);
            packets[i][packet_index+1] &= ~(1<<10);
            packets[i][packet_index+1] &= ~(1<<9);
            packets[i][packet_index+1] &= ~(1<<8);

            packets[i][packet_index+2] = payload_num>>8;
            packets[i][packet_index+2] &= ~(1<<31);
            packets[i][packet_index+2] &= ~(1<<30);
            packets[i][packet_index+2] &= ~(1<<29);
            packets[i][packet_index+2] &= ~(1<<28);
            packets[i][packet_index+2] &= ~(1<<27);
            packets[i][packet_index+2] &= ~(1<<26);
            packets[i][packet_index+2] &= ~(1<<25);
            packets[i][packet_index+2] &= ~(1<<24);
            packets[i][packet_index+2] &= ~(1<<23);
            packets[i][packet_index+2] &= ~(1<<22);
            packets[i][packet_index+2] &= ~(1<<21);
            packets[i][packet_index+2] &= ~(1<<20);
            packets[i][packet_index+2] &= ~(1<<19);
            packets[i][packet_index+2] &= ~(1<<18);
            packets[i][packet_index+2] &= ~(1<<17);
            packets[i][packet_index+2] &= ~(1<<16);
            packets[i][packet_index+2] &= ~(1<<15);
            packets[i][packet_index+2] &= ~(1<<14);
            packets[i][packet_index+2] &= ~(1<<13);
            packets[i][packet_index+2] &= ~(1<<12);
            packets[i][packet_index+2] &= ~(1<<11);
            packets[i][packet_index+2] &= ~(1<<10);
            packets[i][packet_index+2] &= ~(1<<9);
            packets[i][packet_index+2] &= ~(1<<8);

            packets[i][packet_index+3] = payload_num;
            packets[i][packet_index+3] &= ~(1<<31);
            packets[i][packet_index+3] &= ~(1<<30);
            packets[i][packet_index+3] &= ~(1<<29);
            packets[i][packet_index+3] &= ~(1<<28);
            packets[i][packet_index+3] &= ~(1<<27);
            packets[i][packet_index+3] &= ~(1<<26);
            packets[i][packet_index+3] &= ~(1<<25);
            packets[i][packet_index+3] &= ~(1<<24);
            packets[i][packet_index+3] &= ~(1<<23);
            packets[i][packet_index+3] &= ~(1<<22);
            packets[i][packet_index+3] &= ~(1<<21);
            packets[i][packet_index+3] &= ~(1<<20);
            packets[i][packet_index+3] &= ~(1<<19);
            packets[i][packet_index+3] &= ~(1<<18);
            packets[i][packet_index+3] &= ~(1<<17);
            packets[i][packet_index+3] &= ~(1<<16);
            packets[i][packet_index+3] &= ~(1<<15);
            packets[i][packet_index+3] &= ~(1<<14);
            packets[i][packet_index+3] &= ~(1<<13);
            packets[i][packet_index+3] &= ~(1<<12);
            packets[i][packet_index+3] &= ~(1<<11);
            packets[i][packet_index+3] &= ~(1<<10);
            packets[i][packet_index+3] &= ~(1<<9);
            packets[i][packet_index+3] &= ~(1<<8);

            packet_index+=4;
        }

        int checksum = compute_checksum_sf(packets[i]); 
        packets[i][12] = maximum_hop_count;
        packets[i][12] &= ~(1<<4);
        packets[i][12] &= ~(1<<3);
        packets[i][12] &= ~(1<<2);
        packets[i][12] &= ~(1<<1);
        packets[i][12] <<= 8;
        packets[i][12] |= checksum;
        packets[i][12] >>= 25;

        packets[i][13] = checksum>>8;
        packets[i][13] &= ~(1<<22);
        packets[i][13] &= ~(1<<21);
        packets[i][13] &= ~(1<<20);
        packets[i][13] &= ~(1<<19);
        packets[i][13] &= ~(1<<18);
        packets[i][13] &= ~(1<<17);
        packets[i][13] &= ~(1<<16);
        packets[i][13] &= ~(1<<15);
        packets[i][13] &= ~(1<<14);
        packets[i][13] &= ~(1<<13);
        packets[i][13] &= ~(1<<12);
        packets[i][13] &= ~(1<<11);
        packets[i][13] &= ~(1<<10);
        packets[i][13] &= ~(1<<9);
        packets[i][13] &= ~(1<<8);

        packets[i][14] = checksum;
        packets[i][14] &= ~(1<<22);
        packets[i][14] &= ~(1<<21);
        packets[i][14] &= ~(1<<20);
        packets[i][14] &= ~(1<<19);
        packets[i][14] &= ~(1<<18);
        packets[i][14] &= ~(1<<17);
        packets[i][14] &= ~(1<<16);
        packets[i][14] &= ~(1<<15);
        packets[i][14] &= ~(1<<14);
        packets[i][14] &= ~(1<<13);
        packets[i][14] &= ~(1<<12);
        packets[i][14] &= ~(1<<11);
        packets[i][14] &= ~(1<<10);
        packets[i][14] &= ~(1<<9);
        packets[i][14] &= ~(1<<8);


        count_packets++;
    }


    return count_packets;
}
