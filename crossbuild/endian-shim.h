/* darwin non ha le16toh/le32toh (Linux/FreeBSD) — mappa su OSSwap */
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
