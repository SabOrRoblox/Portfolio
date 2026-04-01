/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for 
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for Bob Swing Hash byte input. 
 *
 * BobSwingHash-512 is implemented.
 *
 * Based on pendulum swinging state with custom primitives alpha/beta/gamma/delta/zeta.
 *
 * I place the code that I wrote into public domain, free to use. 
 *
 * I would appreciate if you give credits to this work if you used it to 
 * write or test your code.
 *
 * April 2026. секси бомба 
 * ---------------------------------------------------------------------- */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define rotl64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define rotr64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define ROUNDS 24
#define WORDS 16

#if defined(_MSC_VER)
#define BOB_SWING_CONST(x) x
#else
#define BOB_SWING_CONST(x) x##L
#endif

typedef struct {
    uint64_t l[4][4];
    uint64_t r[4][4];
    uint64_t light[4];
    uint64_t shadow[4];
} State;

static const uint64_t K1 = 0x517cc1b727220a95;
static const uint64_t K2 = 0xFF51AFD7ED558CCD;
static const uint64_t K3 = 0xC4CEB9FE1A85EC53;
static const uint64_t PHI = 0x9E3779B97F4A7C15;
static const uint64_t GAMMA = 0xBF58476D1CE4E5B9;

static const uint64_t RC[32] = {
    BOB_SWING_CONST(0x9E3779B97F4A7C15), BOB_SWING_CONST(0x3C6EF372FE94F82B),
    BOB_SWING_CONST(0xDAE6A5AB3C6EF372), BOB_SWING_CONST(0x785E5CE4DAE6A5AB),
    BOB_SWING_CONST(0x16D6141D785E5CE4), BOB_SWING_CONST(0xB54DCB5616D6141D),
    BOB_SWING_CONST(0x53C5828FB54DCB56), BOB_SWING_CONST(0xF23D39C853C5828F),
    BOB_SWING_CONST(0x90B4F101F23D39C8), BOB_SWING_CONST(0x2F2CA83A90B4F101),
    BOB_SWING_CONST(0xCDA45F732F2CA83A), BOB_SWING_CONST(0x6C1C16ACCDA45F73),
    BOB_SWING_CONST(0x0A93CDE56C1C16AC), BOB_SWING_CONST(0xA90B851E0A93CDE5),
    BOB_SWING_CONST(0x47833C57A90B851E), BOB_SWING_CONST(0xE5FAF39047833C57),
    BOB_SWING_CONST(0x428A2F98E5FAF390), BOB_SWING_CONST(0x71374491428A2F98),
    BOB_SWING_CONST(0xB5C0FBCF71374491), BOB_SWING_CONST(0xE9B5DBA5B5C0FBCF),
    BOB_SWING_CONST(0x3956C25BE9B5DBA5), BOB_SWING_CONST(0x59F111F13956C25B),
    BOB_SWING_CONST(0x923F82A459F111F1), BOB_SWING_CONST(0xAB1C5ED5923F82A4),
    BOB_SWING_CONST(0xD807AA98AB1C5ED5), BOB_SWING_CONST(0x12835B01D807AA98),
    BOB_SWING_CONST(0x243185BE12835B01), BOB_SWING_CONST(0x550C7DC3243185BE),
    BOB_SWING_CONST(0x72BE5D74550C7DC3), BOB_SWING_CONST(0x80DEB1FE72BE5D74),
    BOB_SWING_CONST(0x9BDC06A780DEB1FE), BOB_SWING_CONST(0xC19BF1749BDC06A7)
};

static inline uint64_t alpha(uint64_t a, uint64_t b, uint64_t c, uint64_t r, uint64_t i, uint64_t s) {
    uint64_t base = (a ^ RC[i & 31]) + (b ^ PHI);
    uint64_t x = base ^ rotl64(c, 17) ^ rotr64(~r, 11);
    uint64_t y = x ^ rotl64(x, 5) ^ (~s ^ i);
    return rotr64(y + i, 13) ^ RC[s & 31];
}

static inline uint64_t beta(uint64_t x, uint64_t r, uint64_t i, uint64_t s) {
    uint64_t a = x ^ rotl64(x, 19) ^ rotr64(x, 23);
    uint64_t diff = (a ^ r) + (i ^ s);
    uint64_t z = diff & (rotl64(diff, 5) ^ r);
    uint64_t c = z ^ (~diff & i);
    return c ^ s ^ rotr64(i, 17) ^ rotl64(x, 7);
}

static inline uint64_t gamma(uint64_t a, uint64_t b, uint64_t r, uint64_t i, uint64_t s, uint64_t d) {
    uint64_t x = (a ^ ~b) + (r ^ d) ^ ((a & ~d) | (b & r));
    x ^= rotl64(x, 2) ^ rotr64(x, 7);
    x ^= rotl64(x, 11) ^ rotr64(x, 13);
    x ^= rotl64(x, 17) ^ rotr64(x, 19);
    return x;
}

static inline uint64_t delta(uint64_t a, uint64_t b, uint64_t k, uint64_t r, uint64_t i, uint64_t s) {
    uint64_t ab = a ^ (b + k) ^ i;
    uint64_t abr = ab ^ rotr64(ab, 3) ^ rotl64(~ab, 5) ^ rotl64(ab, 7);
    return r ^ ((r + i) & ~abr) ^ s;
}

static inline uint64_t zeta(uint64_t x, uint64_t r, uint64_t i, uint64_t s) {
    uint64_t mul = ~x + (r ^ i ^ s);
    uint64_t nonlinear = mul ^ rotl64(mul, 13) ^ rotr64(mul, 17);
    return nonlinear ^ rotl64(r, 7) ^ rotr64(i, 11) ^ ~s;
}

static void state_zero(State *st) {
    memset(st, 0, sizeof(State));
}

static void state_iv(State *st) {
    state_zero(st);
    for (int i = 0; i < 4; i++) {
        st->light[i] = zeta(K1 ^ i, PHI, i, GAMMA);
        st->shadow[i] = zeta(K2 ^ i, GAMMA, i, PHI);
    }
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            int idx = (i << 2) + j;
            st->l[i][j] = zeta(K3 ^ st->light[idx & 3], PHI, idx, st->shadow[idx & 3]);
            st->r[i][j] = zeta(GAMMA ^ st->shadow[idx & 3], K1, idx, st->light[idx & 3]);
        }
}

static void load_block(uint64_t out[WORDS], const uint8_t *in) {
    for (int i = 0; i < WORDS; i++) {
        out[i] = (uint64_t)in[i*8] | ((uint64_t)in[i*8+1]<<8) |
                 ((uint64_t)in[i*8+2]<<16) | ((uint64_t)in[i*8+3]<<24) |
                 ((uint64_t)in[i*8+4]<<32) | ((uint64_t)in[i*8+5]<<40) |
                 ((uint64_t)in[i*8+6]<<48) | ((uint64_t)in[i*8+7]<<56);
    }
}

static void process_rounds(State *st, const uint64_t *data, uint64_t block_idx) {
    uint64_t s_val = zeta(block_idx * K1, block_idx, K2, PHI);
    uint64_t idx = block_idx;
    for (int step = 0; step < ROUNDS; step++) {
        uint64_t rc = RC[step & 31];
        uint64_t rnd = step;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int w = (i << 2) + j;
                int li = (w + step) & 3;
                uint64_t lv = st->l[i][j];
                uint64_t rv = st->r[i][j];
                st->light[li] = zeta(st->light[li] ^ lv ^ rv ^ rc, rc, w, rnd);
                st->shadow[li] = gamma(st->shadow[li] ^ rv ^ lv ^ data[w], rc, w, rnd, s_val, K1);
            }
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int w = (i << 2) + j;
                int li = (w + step) & 3;
                uint64_t lv = st->l[i][j];
                uint64_t rv = st->r[i][j];
                st->l[i][j] = alpha(lv, st->light[li], data[w] ^ st->shadow[li], rc, w, rnd);
                st->r[i][j] = delta(rv, st->shadow[li], st->light[li], rc, w, rnd);
                st->l[i][j] = gamma(st->l[i][j], st->light[li], rc, w, rnd, s_val);
                st->r[i][j] = beta(st->r[i][j] ^ st->shadow[li], rc, w, rnd);
            }
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int next = ((i << 2) + ((j + 1) & 3)) & 15;
                int prev = ((i << 2) + ((j + 3) & 3)) & 15;
                st->l[i][j] ^= rotl64(st->r[next >> 2][next & 3], 17);
                st->r[i][j] ^= rotr64(st->l[prev >> 2][prev & 3], 19);
            }
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int w = (i << 2) + j;
                int li = (w + step) & 3;
                st->light[li] ^= st->l[i][j] ^ st->r[i][j];
                st->shadow[li] ^= rotl64(st->r[i][j], 13) ^ rotr64(st->l[i][j], 11);
            }
        }
        s_val = gamma(s_val, rc, PHI, idx, rnd, K1);
        idx = delta(idx, block_idx, K2, rc, rnd, s_val);
    }
}

static void ffinal(State *st, const uint64_t *block, uint64_t block_idx) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            int w = (i << 2) + j;
            uint64_t b = block[w];
            st->l[i][j] ^= b;
            st->light[w & 3] = gamma(st->light[w & 3], b, PHI, w, K1, K2);
            st->shadow[w & 3] = delta(st->shadow[w & 3], b, K3, GAMMA, w, PHI);
        }
    }
    process_rounds(st, block, block_idx);
}

static void finalize_512(State *st, uint8_t out[64], uint64_t total_len) {
    for (int wave = 0; wave < 4; wave++) {
        uint64_t rc = RC[wave & 31];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int idx = (i << 2) + j;
                int li = idx & 3;
                uint64_t lv = st->l[i][j];
                uint64_t rv = st->r[i][j];
                st->l[i][j] = delta(lv ^ total_len, st->shadow[li], rc, idx, wave, K1);
                st->r[i][j] = alpha(rv ^ total_len, st->light[li], rc, PHI, idx, wave);
                st->light[li] ^= rotl64(lv, idx) ^ rotr64(rv, idx);
                st->shadow[li] ^= rotr64(lv, idx) ^ rotl64(rv, idx);
            }
        }
        for (int i = 0; i < 4; i++) {
            st->light[i] = zeta(st->light[i], st->shadow[i], i, rc);
            st->shadow[i] = gamma(st->shadow[i], st->light[i], rc, i, wave, K2);
        }
    }
    uint64_t hash[8] = {0};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            int idx = (i << 2) + j;
            uint64_t mix = st->l[i][j] ^ st->r[i][j] ^ st->light[idx & 3] ^ st->shadow[idx & 3] ^ total_len;
            hash[idx & 7] ^= rotl64(mix, (idx * 7) & 63);
        }
    }
    for (int r = 0; r < 8; r++) {
        hash[r] = alpha(hash[r], hash[(r + 1) & 7], hash[(r + 3) & 7], PHI, r, K1);
        hash[r] = beta(hash[r], GAMMA, r, K2);
        hash[r] = gamma(hash[r], hash[(r + 5) & 7], K3, r, PHI, total_len);
        hash[r] = delta(hash[r], total_len, K1, K2, r, K3);
        hash[r] = zeta(hash[r], hash[(r + 7) & 7], r, PHI);
    }
    for (int swing = 0; swing < 6; swing++) {
        for (int i = 0; i < 4; i++) {
            uint64_t temp_l = st->light[i];
            uint64_t temp_s = st->shadow[i];
            st->light[i] = gamma(temp_l ^ total_len, temp_s, PHI, i, swing, K1);
            st->shadow[i] = delta(temp_s, temp_l, K2, i * swing, swing, K3);
        }
        for (int i = 0; i < 8; i++) {
            hash[i] = zeta(hash[i] ^ st->light[i & 3], hash[(i+1)&7], i, total_len ^ swing);
        }
    }
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (hash[i] >> (j * 8)) & 0xFF;
}

static void compute_hash(const uint8_t *input, size_t len, uint8_t output[64]) {
    State st;
    state_iv(&st);
    uint64_t block[WORDS];
    size_t num_blocks = len / 128;
    for (size_t blk = 0; blk < num_blocks; blk++) {
        load_block(block, input + blk * 128);
        ffinal(&st, block, blk);
    }
    size_t rem = len % 128;
    uint8_t last_bytes[128] = {0};
    if (rem) memcpy(last_bytes, input + num_blocks * 128, rem);
    last_bytes[rem] = 0x80;
    load_block(block, last_bytes);
    if (rem + 1 + 8 > 128) {
        ffinal(&st, block, num_blocks);
        memset(last_bytes, 0, 128);
        last_bytes[120] = (uint8_t)(len << 3);
        last_bytes[121] = (uint8_t)(len >> 5);
        last_bytes[122] = (uint8_t)(len >> 13);
        last_bytes[123] = (uint8_t)(len >> 21);
        last_bytes[124] = (uint8_t)(len >> 29);
        last_bytes[125] = (uint8_t)(len >> 37);
        last_bytes[126] = (uint8_t)(len >> 45);
        last_bytes[127] = (uint8_t)(len >> 53);
        load_block(block, last_bytes);
        ffinal(&st, block, num_blocks + 1);
    } else {
        block[15] = len << 3;
        ffinal(&st, block, num_blocks);
    }
    finalize_512(&st, output, len);
}

int main(int argc, char **argv) {
    const char *input_str = NULL;
    int verbose = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
            input_str = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
    }
    if (!input_str) {
        fprintf(stderr, "Usage: %s -s <string> [-v]\n", argv[0]);
        return 1;
    }
    size_t len = strlen(input_str);
    uint8_t hash[64];
    compute_hash((const uint8_t*)input_str, len, hash);
    if (verbose) {
        printf("Hash: ");
        for (int i = 0; i < 64; i++) printf("%02x", hash[i]);
        printf("\nSize: %zu bytes\n", len);
    } else {
        for (int i = 0; i < 64; i++) printf("%02x", hash[i]);
        printf("\n");
    }
    return 0;
}
