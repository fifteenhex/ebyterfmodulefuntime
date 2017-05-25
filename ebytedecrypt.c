#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "sx127x.h"

static uint8_t secretkey[58] = {
	0x68, 0x70, 0x78, 0x80, 0x88,
	0x91, 0x99, 0xa1, 0xa9, 0xb1,
	0xb9, 0x6b, 0xc9, 0xd2, 0xda,
	0xe2, 0xea, 0xf2, 0xfa, 0x02,
	0x0a, 0x13, 0x1b, 0x23, 0x2b,
	0x33, 0x3b, 0x43, 0x4b, 0x4c,
	0x54, 0x5c, 0x64, 0x6c, 0x74,
	0x7c, 0x84, 0x8d, 0x95, 0x9d,
	0xa5, 0xad, 0xb5, 0xdd, 0xc5,
	0xce, 0xd6, 0xde, 0xe6, 0xee,
	0xf6, 0xfe, 0x06, 0x0f, 0x17,
	0x1f, 0x27
};

int main(int argc, char** argv) {

	int fd = open("/dev/sx127x0", O_RDWR);

	if (fd < 0)
		printf("failed to open device\n");

	void* buff = malloc(1024);

	while(1){
		read(fd, buff, sizeof(size_t));
		read(fd, buff + sizeof(size_t), *((size_t*) buff));

		struct sx127x_pkt* pkt = buff;
		uint8_t* payload = buff + pkt->hdrlen;

		uint8_t len = *payload++;
		if(len + 5 != pkt->payloadlen){
			printf("length in message doesn't match expected\n");
			continue;
		}

		uint8_t whoknows = *payload++;
		uint8_t addrmsb = *payload++;
		uint8_t addrlsb = *payload++;

		printf("%d bytes for %02x%02x\n", len, addrmsb, addrlsb);
		for(int i = 0; i < len; i++){
			printf("%02x:", payload[i]);
			payload[i] ^= secretkey[len-1];
			printf("%02x\n", payload[i]);
		}

	}


	return 0;
}

