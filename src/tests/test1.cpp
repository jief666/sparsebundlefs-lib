#include "../sparsebundlefs/sparsebundlefs.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>


void printBuf(uint8_t* buf, size_t count)
{
	for (size_t i = 0; i < count;) {
		for (int j = 0; j < 16; j++)
			printf("%02x ", (uint8_t) (buf[i + j]));
		for (size_t j = 0; j < 16; j++) {
			if (buf[i + j] >= 32)
				printf("%c ", (uint8_t) (buf[i + j]));
			else
				printf("  ");
		}
		i += 16;
		if (i % 16 == 0)
			printf("\n");
	}
}

int test1(void* sparsebundle_data, const char* path, off_t offset, const char* expectedResult, size_t expectedResultLength)
{
  uint8_t buf[expectedResultLength+3000];
  size_t rv;


	rv = sparsebundlefs_read(sparsebundle_data, buf, sizeof(buf), offset);
	if ( rv < expectedResultLength )
	{
		printf("ERROR in '%s' at offset %llu. read return %zd, errno %d\n", path, offset, rv, errno);
		return 1;
	}
	if ( memcmp(buf, expectedResult, expectedResultLength) != 0 ) {
		printf("ERROR in '%s' at offset %llu. memory differs\n", path, offset);
		printBuf(buf, 64);
		return 1;
	}
	return 0;
}



int main(int argc, char**argv)
{
  int nbFailed = 0;
  int rv;

uint8_t sparsebundle_data[sparsebundlefs_getdatasize()];

	const char* path1 = "Test1.sparsebundle";

	printf("%s\n", path1);
  	rv = sparsebundlefs_open(path1, NULL, &sparsebundle_data);
	if ( rv != 0 )
	{
		printf("ERROR Cannot open '%s' : returned %d, errno %d\n", path1, rv, errno);
		return 1;
	}
//	printf("sparsebundlefs_open return %d, errno=%d\n", rv, errno);

	{
		const char* expectedResult1 = "\x48\x2B\x00\x04\x80\x00\x21\x00\x48\x46\x53\x4A\x00\x00\x00\x02";
		nbFailed += test1(&sparsebundle_data, path1, 1024, expectedResult1, sizeof(expectedResult1));
	}
	{
		const char* expectedResult1 = "\x63\x69\x20\x65\x67\x65\x74\x20\x61\x6C\x69\x71\x75\x61\x6D\x20";
		nbFailed += test1(&sparsebundle_data, path1, 1048568, expectedResult1, sizeof(expectedResult1));
	}


	const char* path2 = "Test1Enc.sparsebundle";
	printf("%s\n",path2);
  	rv = sparsebundlefs_open("Test1Enc.sparsebundle", "foo", &sparsebundle_data);
	if ( rv != 0 )
	{
		printf("ERROR Cannot open '%s' : returned %d, errno %d\n",path2, rv, errno);
		return 1;
	}

	{
		const char* expectedResult1 = "\x48\x2B\x00\x04\x80\x00\x21\x00\x48\x46\x53\x4A\x00\x00\x00\x02";
		nbFailed += test1(&sparsebundle_data, path2, 1024, expectedResult1, sizeof(expectedResult1));
	}
	{
		const char* expectedResult1 = "\x69\x73\x20\x64\x69\x73\x20\x70\x61\x72\x74\x75\x72\x69\x65\x6E";
		nbFailed += test1(&sparsebundle_data, path2, 1048568, expectedResult1, sizeof(expectedResult1));
	}
	if ( nbFailed == 0 ) printf("************** OK ***************\n");
	if ( nbFailed != 0 ) printf("************** %d FAILED ***************\n", nbFailed);

}
