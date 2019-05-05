
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LB64_INVALID_CODE 64
#define LB64_PADDING_CHAR 65
#define LB64_SPACE_CHAR 66

#define LB64_UNEXPECTED_END 2
#define LB64_OK 0


char *lb64_bin2string(const char* dest, unsigned char *source, size_t len, int *err);
unsigned char *lb64_string2bin(unsigned char *dest, size_t *decoded_len_, size_t max_len, char *source, int *err);


#ifdef __cplusplus
}
#endif