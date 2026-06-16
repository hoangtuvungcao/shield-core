#include "dpi.h"
#include <string.h>

bool dpi_validate_a2s_query(const uint8_t *payload, uint32_t len) {
    // A2S_INFO query standard size is 25 bytes minimum
    // Payload starts with 0xFF 0xFF 0xFF 0xFF 0x54 "Source Engine Query\0"
    if (len < 25) {
        return false;
    }
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) {
        return false;
    }
    if (payload[4] != 0x54) {
        return false;
    }
    if (memcmp(payload + 5, "Source Engine Query", 19) != 0) {
        return false;
    }
    return true;
}
