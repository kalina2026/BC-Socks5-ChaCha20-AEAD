// compile: tcc socks4_win_proxy.c -lws2_32 -o socks4_win_proxy.exe
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "CORE_CRYPTOGRAPHIC_ENGINE.c"

#define PROXY_PORT 1080
#define BUF_SIZE 8192

static int sec = 0; 
static int latched = 0;   
static CRITICAL_SECTION lock;  

/* !!! CHANGE THIS KEY BEFORE COMPILING !!! */ 
static uint8_t global_key[32] = { [0 ... 31] = 0x42 };

typedef struct {
    uint8_t key[32];         
    uint8_t ctx_nonce[12];   
    union {
        uint8_t raw[BUF_SIZE];
        struct {
            uint32_t len_le;
            uint8_t nonce[12];
            uint8_t payload[BUF_SIZE - 32];
            uint8_t tag[16];
        };
    } b;
} bc_ctx;

static bc_ctx static_contexts[2]; 

void inc_nonce(uint8_t *n) {
    for(int i = 0; i < 12; i++) {
        if(++n[i] != 0) break;
    }
}

void x_send_ctx(SOCKET fd, int len, bc_ctx *ctx, int s_mode, const char* label) {
    if (s_mode) {
        memcpy(ctx->b.nonce, ctx->ctx_nonce, 12); 
        br_enc32le(&ctx->b.len_le, (uint32_t)len);
        br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, (size_t)len, ctx->b.raw, 16, ctx->b.payload + len, br_chacha20_ct_run, 1);
        send(fd, (char*)ctx->b.raw, 16 + len + 16, 0);
        inc_nonce(ctx->ctx_nonce);
        // printf("[%s] Sent Encrypted: %d bytes\n", label, len);
    } else {
        send(fd, (char*)ctx->b.payload, len, 0);
    }
}

int x_recv_ctx(SOCKET fd, bc_ctx *ctx, int s_mode, const char* label) {
    if (s_mode) {
        if (recv(fd, (char*)ctx->b.raw, 16, MSG_WAITALL) <= 0) return -1;
        uint32_t len = br_dec32le(&ctx->b.len_le);
        if (len > (BUF_SIZE - 32)) return -1; 
        if (recv(fd, (char*)ctx->b.payload, len + 16, MSG_WAITALL) <= 0) return -1;
        
        uint8_t tag[16];
        br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, (size_t)len, ctx->b.raw, 16, tag, br_chacha20_ct_run, 0);
        
        if (memcmp(tag, ctx->b.payload + len, 16) != 0) {
            printf("[!] %s MAC ERROR! Decryption failed.\n", label);
            return -1;
        }
        inc_nonce(ctx->ctx_nonce); 
        return (int)len; 
    }
    return recv(fd, (char*)ctx->b.payload, BUF_SIZE - 32, 0);
}

void tunnel(SOCKET client, SOCKET server, bc_ctx *ctx, int s_mode, const char* label) {
    fd_set fds;
    while (1) {
        FD_ZERO(&fds); FD_SET(client, &fds); FD_SET(server, &fds);
        if (select(0, &fds, NULL, NULL, NULL) <= 0) break;
        
        if (FD_ISSET(client, &fds)) {
            int n = recv(client, (char*)ctx->b.payload, BUF_SIZE - 32, 0);
            if (n <= 0) break;
            x_send_ctx(server, n, ctx, s_mode, label);
        }
        if (FD_ISSET(server, &fds)) {
            int n = x_recv_ctx(server, ctx, s_mode, label);
            if (n <= 0) break;
            send(client, (char*)ctx->b.payload, n, 0);
        }
    }
}

DWORD WINAPI handle_bc_client(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    unsigned char s4[8];
    struct sockaddr_in saddr = {AF_INET};
    int is_control_conn = 0;

    if (recv(client, (char*)s4, 8, MSG_WAITALL) <= 0) goto cleanup;
    saddr.sin_port = *(unsigned short*)(s4 + 2);
    saddr.sin_addr.s_addr = *(unsigned int*)(s4 + 4);
    int target_p = ntohs(saddr.sin_port);

    char junk;
    while (recv(client, &junk, 1, 0) > 0 && junk != 0);

    EnterCriticalSection(&lock);
    if (!latched) {
        latched = 1;
        is_control_conn = 1; 
        sec = (target_p == 2122) ? 1 : 0;
        printf("\n[NEW SESSION] Control: %s (Port %d)\n", sec ? "SECURE" : "PLAIN", target_p);
    }
    int current_sec = sec;
    LeaveCriticalSection(&lock);

    // FIX: Match the server logic - every connection (cmd or data) gets a fresh key/salt sync
    bc_ctx *ctx = &static_contexts[is_control_conn ? 0 : 1];
    memset(ctx, 0, sizeof(bc_ctx)); 
    memcpy(ctx->key, global_key, 32);

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(server, (struct sockaddr*)&saddr, sizeof(saddr)) == SOCKET_ERROR) {
        unsigned char fail[] = {0x00, 0x5B, 0,0, 0,0,0,0};
        send(client, (char*)fail, 8, 0);
        goto release_latch;
    }

    if (current_sec) {
        printf("[DEBUG] Waiting for Salt from Server for Port %d...\n", target_p);
        if (recv(server, (char*)ctx->ctx_nonce, 12, MSG_WAITALL) <= 0) {
            printf("[!] Failed to recv salt\n");
            closesocket(server);
            goto release_latch;
        }
        printf("[DEBUG] Salt Recv: %02X%02X... Context: %s\n", ctx->ctx_nonce[0], ctx->ctx_nonce[1], is_control_conn ? "CMD" : "DATA");
    }

    unsigned char success[] = {0x00, 0x5A, 0,0, 0,0,0,0};
    send(client, (char*)success, 8, 0);

    tunnel(client, server, ctx, current_sec, is_control_conn ? "CMD" : "DATA");
    printf("[CLOSE] %s connection closed.\n", is_control_conn ? "CMD" : "DATA");
    closesocket(server);

release_latch:
    if (is_control_conn) {
        EnterCriticalSection(&lock);
        latched = 0;
        printf("[LATCH] Released.\n");
        LeaveCriticalSection(&lock);
    }
cleanup:
    closesocket(client);
    return 0;
}

int main() {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&lock);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {AF_INET, htons(PROXY_PORT), .sin_addr.s_addr = inet_addr("127.0.0.1")};
    bind(ls, (struct sockaddr*)&addr, sizeof(addr));
    listen(ls, SOMAXCONN);
    printf("Proxy Active on 1080. Awaiting BC client...\n");
    while (1) {
        SOCKET c = accept(ls, NULL, NULL);
        if (c != INVALID_SOCKET) CreateThread(NULL, 0, handle_bc_client, (LPVOID)c, 0, NULL);
    }
    return 0;
}
