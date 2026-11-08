// crack3: in-process wordlist + rule engine for JWT HS256 secret cracking.
// usage: ./crack3 target.jwt wordlist.txt [threads] [profile]
// profile 0 = light (case+suffix+year), 1 = full (+leet/prepend/reverse)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>

static unsigned char sig[64];
static int siglen = 32;
static unsigned char *msg = NULL;
static size_t msglen = 0;
static volatile int done = 0;
static char found[1024];
static long long checked = 0;
static pthread_mutex_t accmtx = PTHREAD_MUTEX_INITIALIZER;
static char *g_buf;
static size_t g_len;
static int g_profile = 1;

static inline void hmac_sha256(const unsigned char *k, size_t kl,
                               const unsigned char *m, size_t ml, unsigned char *out) {
    unsigned char k0[64];
    memset(k0, 0, 64);
    if (kl > 64) SHA256(k, kl, k0); else memcpy(k0, k, kl);
    unsigned char ip[64], op[64];
    for (int i = 0; i < 64; i++) { ip[i] = k0[i] ^ 0x36; op[i] = k0[i] ^ 0x5c; }
    SHA256_CTX c; unsigned char ih[32];
    SHA256_Init(&c); SHA256_Update(&c, ip, 64); SHA256_Update(&c, m, ml); SHA256_Final(ih, &c);
    SHA256_Init(&c); SHA256_Update(&c, op, 64); SHA256_Update(&c, ih, 32); SHA256_Final(out, &c);
}

static void hit(const char *s, int len) {
    pthread_mutex_lock(&accmtx);
    if (!done) {
        int n = len < 1023 ? len : 1023;
        memcpy(found, s, n); found[n] = 0; done = 1;
        FILE *f = fopen("FOUND_SECRET.txt", "a");
        if (f) { fprintf(f, "%s\n", found); fclose(f); }
    }
    pthread_mutex_unlock(&accmtx);
}

static inline void try_cand(char *buf, int len, long long *cnt) {
    unsigned char out[32];
    hmac_sha256((unsigned char*)buf, (size_t)len, msg, msglen, out);
    (*cnt)++;
    if (out[0]==sig[0] && memcmp(out, sig, siglen)==0) hit(buf, len);
}

static const char *SUF[] = {
    "","1","12","123","1234","12345","123456","1234567","12345678","123456789",
    "0","00","01","007","11","111","1111","69","666","777","888","999",
    "2020","2021","2022","2023","2024","2025","2026","2027","2028",
    "!","@","#","$","%","&","*",".","_","-",
    "!!","!!!","@!","!@","!@#","@#$","!@#$","123!","123@","123#","1234!","12345!",
    "2026!","2026@","2026#","2026!@#","!2026","@2026","#2026","2024!","2025!",
    "@123","#123","!123","@1234","!@#123","1!","1@","1#","12!","123abc"
};
#define NSUF (int)(sizeof(SUF)/sizeof(SUF[0]))

static inline void leetify(const char *w, int len, char *out, int *olen) {
    int o = 0;
    for (int i = 0; i < len; i++) {
        char c = w[i];
        switch (c) {
            case 'a': case 'A': out[o++]='@'; break;
            case 'e': case 'E': out[o++]='3'; break;
            case 'i': case 'I': out[o++]='1'; break;
            case 'o': case 'O': out[o++]='0'; break;
            case 's': case 'S': out[o++]='$'; break;
            case 't': case 'T': out[o++]='7'; break;
            case 'l': case 'L': out[o++]='1'; break;
            default: out[o++]=c;
        }
    }
    *olen = o;
}

static void process_word(char *w, int len, long long *cnt) {
    if (len <= 0 || len > 200) return;
    char ws[256]; memcpy(ws, w, len); ws[len] = 0;
    char b[512]; int n;
    // original
    memcpy(b, w, len); try_cand(b, len, cnt);
    // lower / upper / capitalize
    memcpy(b, w, len);
    for (int i=0;i<len;i++) if (b[i]>='A'&&b[i]<='Z') b[i]+=32;
    try_cand(b, len, cnt);
    memcpy(b, w, len);
    for (int i=0;i<len;i++) if (b[i]>='a'&&b[i]<='z') b[i]-=32;
    try_cand(b, len, cnt);
    memcpy(b, w, len);
    if (b[0]>='a'&&b[0]<='z') b[0]-=32;
    try_cand(b, len, cnt);
    // suffixes
    for (int s = 0; s < NSUF; s++) {
        int sl = (int)strlen(SUF[s]);
        if (len + sl > 250) continue;
        memcpy(b, w, len); memcpy(b+len, SUF[s], sl);
        try_cand(b, len+sl, cnt);
        if (done) return;
    }
    // capitalize + suffix
    memcpy(b, w, len);
    if (b[0]>='a'&&b[0]<='z') b[0]-=32;
    for (int s = 1; s < NSUF; s += 2) {
        int sl = (int)strlen(SUF[s]);
        if (len + sl > 250) continue;
        memcpy(b+len, SUF[s], sl);
        try_cand(b, len+sl, cnt);
        if (done) return;
    }
    if (g_profile >= 1) {
        // leet
        int ol; char lb[256];
        leetify(w, len, lb, &ol);
        memcpy(b, lb, ol); try_cand(b, ol, cnt);
        for (int s = 1; s < NSUF; s += 3) {
            int sl = (int)strlen(SUF[s]);
            if (ol + sl > 250) continue;
            memcpy(b, lb, ol); memcpy(b+ol, SUF[s], sl);
            try_cand(b, ol+sl, cnt);
            if (done) return;
        }
        // reverse
        for (int i=0;i<len;i++) b[i]=w[len-1-i];
        try_cand(b, len, cnt);
        // duplicate
        if (len*2 <= 250) { memcpy(b,w,len); memcpy(b+len,w,len); try_cand(b, len*2, cnt); }
        // prepend years 2018-2027
        for (int y = 2018; y <= 2027; y++) {
            n = snprintf(b, sizeof b, "%d", y); memcpy(b+n, w, len);
            try_cand(b, n+len, cnt);
            if (done) return;
        }
        // word+sep+year
        const char *seps[] = {"_","-",".","@","#"};
        for (int si=0; si<5; si++) for (int y=2022; y<=2027; y++) {
            n = snprintf(b, sizeof b, "%s%s%d", ws, seps[si], y);
            try_cand(b, n, cnt);
            if (done) return;
        }
        // word + symbol + year
        for (int y=2024; y<=2026; y++) {
            n = snprintf(b, sizeof b, "%s!%d", ws, y); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s@%d", ws, y); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s#%d", ws, y); try_cand(b, n, cnt);
            if (done) return;
        }
    }
    if (g_profile >= 2) {
        for (int d = 0; d < 1000; d++) {
            n = snprintf(b, sizeof b, "%s%03d", ws, d); try_cand(b, n, cnt);
            if (done) return;
        }
        for (int d = 0; d < 100; d++) {
            n = snprintf(b, sizeof b, "%s!%02d", ws, d); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s@%02d", ws, d); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s#%02d", ws, d); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s%02d!", ws, d); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s%02d@", ws, d); try_cand(b, n, cnt);
            if (done) return;
        }
        for (int y = 1950; y <= 2030; y++) {
            n = snprintf(b, sizeof b, "%s%d", ws, y); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%d%s", y, ws); try_cand(b, n, cnt);
            if (done) return;
        }
    }
    if (g_profile >= 3) {
        for (int d = 0; d < 10000; d++) {
            n = snprintf(b, sizeof b, "%s%04d", ws, d); try_cand(b, n, cnt);
            if (done) return;
        }
        for (int d = 0; d < 1000; d++) {
            n = snprintf(b, sizeof b, "%s!%03d", ws, d); try_cand(b, n, cnt);
            n = snprintf(b, sizeof b, "%s@%03d", ws, d); try_cand(b, n, cnt);
            if (done) return;
        }
    }
}

typedef struct { char *s, *e; } range_t;

static void *worker(void *arg) {
    range_t *r = (range_t*)arg;
    long long local = 0;
    char *p = r->s, *end = r->e;
    while (p < end && !done) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t l = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (l && p[l-1] == '\r') l--;
        if (l > 0) process_word(p, (int)l, &local);
        if (!nl) break;
        p = nl + 1;
    }
    pthread_mutex_lock(&accmtx); checked += local; pthread_mutex_unlock(&accmtx);
    return NULL;
}

static int b64url_decode(const char *s, unsigned char *out) {
    int len = 0; unsigned int buf = 0; int bits = 0;
    for (const char *p = s; *p; p++) {
        int v;
        if (*p >= 'A' && *p <= 'Z') v = *p - 'A';
        else if (*p >= 'a' && *p <= 'z') v = *p - 'a' + 26;
        else if (*p >= '0' && *p <= '9') v = *p - '0' + 52;
        else if (*p == '-') v = 62;
        else if (*p == '_') v = 63;
        else if (*p == '=') break;
        else continue;
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out[len++] = (buf >> bits) & 0xff; }
    }
    return len;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s target.jwt wordlist [threads] [profile]\n", argv[0]); return 2; }
    FILE *tf = fopen(argv[1], "r");
    if (!tf) { perror("target"); return 2; }
    static char tok[8192];
    if (!fgets(tok, sizeof(tok), tf)) return 2;
    int l = strlen(tok); while (l > 0 && (tok[l-1]=='\n'||tok[l-1]=='\r'||tok[l-1]==' ')) tok[--l]=0;
    char *p1 = strchr(tok, '.'); if (!p1) return 2;
    char *p2 = strchr(p1+1, '.'); if (!p2) return 2;
    *p2 = 0;
    msg = (unsigned char*)strdup(tok); msglen = strlen(tok);
    siglen = b64url_decode(p2+1, sig);
    int nth = argc > 3 ? atoi(argv[3]) : 16;
    if (nth < 1) nth = 1; if (nth > 64) nth = 64;
    if (argc > 4) g_profile = atoi(argv[4]);
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) { perror("wordlist"); return 2; }
    struct stat st; fstat(fd, &st);
    g_len = st.st_size;
    g_buf = mmap(NULL, g_len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (g_buf == MAP_FAILED) { perror("mmap"); return 2; }
    fprintf(stderr, "signing_input_len=%zu siglen=%d words=%zu threads=%d profile=%d\n", msglen, siglen, g_len, nth, g_profile);

    range_t *r = malloc(sizeof(range_t)*nth);
    pthread_t th[64];
    size_t per = g_len / (size_t)nth;
    if (per == 0) per = 1;
    char *s = g_buf; int k = 0;
    for (int i = 0; i < nth; i++) {
        if (s >= g_buf + g_len) break;
        char *e = (i == nth-1) ? g_buf + g_len : s + per;
        if (e > g_buf + g_len) e = g_buf + g_len;
        char *al = e;
        while (al < g_buf + g_len && al[-1] != '\n') al++;
        r[k].s = s; r[k].e = al; k++;
        s = al;
    }
    for (int i = 0; i < k; i++) pthread_create(&th[i], NULL, worker, &r[i]);
    for (int i = 0; i < k; i++) pthread_join(th[i], NULL);
    fprintf(stderr, "checked=%lld found=%s\n", checked, done ? found : "(none)");
    return done ? 0 : 1;
}
