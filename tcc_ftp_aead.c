/*
 * Portable True Open C Source of AEAD Linux FTP Server
 * --------------------------------------------------------
 * Includes CORE_CRYPTOGRAPHIC_ENGINE.c source code extracted from bearSSL
 * Features: Auto-IP Detection, Permanent Dual-Port Bind,
 * Random Nonce, Triple-Timeout, and Full Command Set (MFMT, MLSD, MDTM).
 * Non-blocking Data Channel Accept to satisfy AEAD Proxy handshakes.
 * --------------------------------------------------------
 * Build: tcc -o tcc_ftp_aead tcc_ftp_aead.c
 * Usage: ./tcc_ftp_aead [root] [optional_ip_override_for_Chromebook]
 * NOTE: if your Linux does't have 200KB tcc you should get it: "sudo apt install tcc"
 * --------------------------------------------------------
 * LICENSE: MIT (Free, no-strings-attached)
 * ORIGIN: Human + Gemini 3 Flash + Copilot (Refined)
 * * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies.
 * * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 * --------------------------------------------------------
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <utime.h>
#include <fcntl.h>
#include <poll.h>
#include "CORE_CRYPTOGRAPHIC_ENGINE.c"

#define AEAD_ONLY
/* !!! CHANGE THIS KEY BEFORE COMPILING !!! */
static const uint8_t global_key[32] = { [ 0 ... 31 ] = 0x42 };

static const char u_key[] = "vpn"; static const char p_key[] = "vpn";

//#define DEBUG

#define BUF_SIZE 8192
#define MAX_PATH 4096

#ifdef DEBUG
void log_to_file(char wh, const uint8_t *data, int len) {
    int fd = open("traffic_log.bin", O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd != -1) {
        write(fd, &wh, 1);
        for (int i = 0; i < len; i++) {
            char c = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
            write(fd, &c, 1);
        }
        write(fd, "\r\n", 2); 
        char hex_buf[4];
        for (int i = 0; i < len; i++) {
            int hlen = sprintf(hex_buf, "%02X ", data[i]);
            write(fd, hex_buf, hlen);
        }
        write(fd, "\r\n\r\n", 4); 
		fsync(fd);  // Force the OS to write to disk NOW
        close(fd);
    }
}
void log_traffic(const char *prefix, const uint8_t *data, int len) {
    printf("--- %s (%d bytes) ---\n", prefix, len);
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {
            int j = i - (i % 16);
            printf(" | ");
            for (; j <= i; j++) printf("%c", (data[j] >= 32 && data[j] <= 126) ? data[j] : '.');
            printf("\n");
        }
    }
}
#endif

typedef struct {
    uint8_t key[32];         // The secret 0x42 key
    uint8_t ctx_nonce[12];   // The "Memory" for this specific TCP link (Salt + Counter)
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

void init_conn_sec(int fd, bc_ctx *ctx) {
    
    // 1. Generate 12-byte random salt
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd >= 0) {
        read(rfd, ctx->ctx_nonce, 12);
        close(rfd);
    } else {
        // Fallback if urandom fails
        uint64_t t = (uint64_t)time(NULL);
        memcpy(ctx->ctx_nonce, &t, 8);
        memset(ctx->ctx_nonce + 8, 0xAA, 4);
    }

    // 2. Send the salt RAW to the proxy
    send(fd, ctx->ctx_nonce, 12, 0);
    
    // 3. Initialize the key (if not already set)
    memcpy(ctx->key, global_key, 32); 
    printf("[SEC] Salt sent for fd %d: %02X%02X...\n", fd, ctx->ctx_nonce[0], ctx->ctx_nonce[1]);
}

static bc_ctx cmd_ctx;
static bc_ctx data_ctx; // isolated context for data transfer
static int sec = 0; // Default to plain
static int pending_data_fd = -1;
int data_listener = -1; char global_ip_comma[64] = "127,0,0,1"; 
static char root_dir[MAX_PATH]; static char buf[1024];

void inc_nonce(uint8_t *n) {
    for(int i = 0; i < 12; i++) if(++n[i] != 0) break;
}


void x_send_ctx(int fd, int len, bc_ctx *ctx) {
    if (sec) {
        memcpy(ctx->b.nonce, ctx->ctx_nonce, 12); 
        br_enc32le(&ctx->b.len_le, (uint32_t)len);
        br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, len, ctx->b.raw, 16, ctx->b.payload + len, br_chacha20_ct_run, 1);
        send(fd, ctx->b.raw, 16 + len + 16, 0);
        inc_nonce(ctx->ctx_nonce);
    } else send(fd, ctx->b.payload, len, 0);
}

int x_recv_ctx(int fd, bc_ctx *ctx) {
    if (sec) {
        if (recv(fd, ctx->b.raw, 16, MSG_WAITALL) <= 0) return -1;
        uint32_t len = br_dec32le(&ctx->b.len_le);
        if (len > (BUF_SIZE - 32)) return -1; 
        if (recv(fd, ctx->b.payload, len + 16, MSG_WAITALL) <= 0) return -1;
        uint8_t computed_tag[16];
        // Decrypt using packet's nonce, then verify
		// TODO: need to add check with local counter
        br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, len, ctx->b.raw, 16, computed_tag, br_chacha20_ct_run, 0);
        if (memcmp(computed_tag, ctx->b.payload + len, 16) != 0) return -1;
        inc_nonce(ctx->ctx_nonce);
        return (int)len; 
    }
    return recv(fd, ctx->b.payload, BUF_SIZE - 32, 0);
}

void send_s(int s, const char* msg) {
    int len = (int)strlen(msg);
    if (len > (BUF_SIZE - 32)) return;
    memcpy(cmd_ctx.b.payload, msg, len);
    x_send_ctx(s, len, &cmd_ctx); 
#ifdef DEBUG
    log_to_file('>',(uint8_t *)msg, len); 
#endif      
}

void clean_cmd(char* t) { for(int i=0; t[i]; i++) if(t[i]=='\r' || t[i]=='\n') t[i] = 0; }

int get_lp(char* lp, const char* cur, const char* fn) {
    if (fn && strstr(fn, "..")) return 0;
    if (fn && fn[0] == '/') sprintf(lp, "%s/%s", root_dir, fn+1);
    else sprintf(lp, "%s%s/%s", root_dir, strcmp(cur,"/")==0?"":cur, fn?fn:"");
    return 1;
}

void send_list_data(const char* v_path, int is_mlsd) {
    int cl = pending_data_fd; pending_data_fd = -1;
    if (cl == -1) { // Fallback accept if not pre-accepted
        struct sockaddr_in da; socklen_t dl = sizeof(da);
    printf("[DATA] Waiting for not pre-accepted connection on data port.\n");
        cl = accept(data_listener, (struct sockaddr*)&da, &dl);
        if (cl != -1 && sec) init_conn_sec(cl, &data_ctx);
    }
    if (cl != -1) {
        char lp[MAX_PATH]; get_lp(lp, v_path, NULL); DIR *d = opendir(lp);
        if (d) {
            struct dirent *dir; struct stat st; char fpath[MAX_PATH]; 
            const char* mos[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_name[0] == '.') continue;
                sprintf(fpath, "%s/%s", lp, dir->d_name);
                if (stat(fpath, &st) == 0) {
                    struct tm *tm = gmtime(&st.st_mtime);
                    char *out = (char*)data_ctx.b.payload;
                    int l;
                    if (is_mlsd) l = sprintf(out, "modify=%04d%02d%02d%02d%02d%02d;type=%s;size=%ld; %s\r\n", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, S_ISDIR(st.st_mode)?"dir":"file", (long)st.st_size, dir->d_name);
                    else l = sprintf(out, "%crwxr-xr-x 1 ftp ftp %ld %s %02d %02d:%02d %s\r\n", S_ISDIR(st.st_mode)?'d':'-', (long)st.st_size, mos[tm->tm_mon], tm->tm_mday, tm->tm_hour, tm->tm_min, dir->d_name);
                    x_send_ctx(cl, l, &data_ctx);
 #ifdef DEBUG
 //                  log_traffic(is_mlsd ? "MLSD_OUT" : "LIST_OUT", (uint8_t*)out, l);
 #endif                  
                }
            }
            closedir(d);
        }
        printf("[DATA] Transfer complete. Closing data socket.\n");
        close(cl);
    }
}

int file_op(const char* v_path, const char* fn, int is_retr) {
    int cl = pending_data_fd; pending_data_fd = -1;
    if (cl == -1) {
        struct sockaddr_in da; socklen_t dl = sizeof(da);
        cl = accept(data_listener, (struct sockaddr*)&da, &dl);
        if (cl != -1 && sec) init_conn_sec(cl, &data_ctx);
    }
    int ok = 0;
    if (cl != -1) {

        char lp[MAX_PATH]; get_lp(lp, v_path, fn);
        FILE* f = fopen(lp, is_retr ? "rb" : "wb");
        if (f) {
            ok = 1; int n, chk = BUF_SIZE - 32; 
            if (is_retr) { while ((n = (int)fread(data_ctx.b.payload, 1, chk, f)) > 0) x_send_ctx(cl, n, &data_ctx); }
            else { while ((n = x_recv_ctx(cl, &data_ctx)) > 0) { if((int)fwrite(data_ctx.b.payload, 1, n, f) < n) { ok = 0; break; } } }
            fclose(f);
        } close(cl);
    } return ok;
}

int setup_listener(int port) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    //// REMOVED: handled by poll now; Timeout for the listener itself
    //struct timeval tv_wait = {60, 0}; 
    //setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, &tv_wait, sizeof(tv_wait));
    struct sockaddr_in daddr = {AF_INET, INADDR_ANY, .sin_port = htons(port)};
    if (bind(ls, (struct sockaddr*)&daddr, sizeof(daddr)) < 0) {
        perror("bind"); exit(1);
    }
    listen(ls, 1);
    return (ls);
}

int main(int argc, char* argv[]) {
    if (!isatty(STDIN_FILENO)) { snprintf(buf, sizeof(buf), "x-terminal-emulator -e '%s' &", argv[0]); system(buf); return 0; }
    prctl(PR_SET_PDEATHSIG, SIGHUP); signal(SIGPIPE, SIG_IGN);
    char *target = (argc > 1 && strcmp(argv[1], "~") != 0) ? argv[1] : getenv("HOME");
    if (target) chdir(target); getcwd(root_dir, MAX_PATH);

    // IP Detection Logic
    char local_ip[64] = "127.0.0.1";
    if (argc > 2) strncpy(local_ip, argv[2], 63);
    else {
        int s_ip = socket(AF_INET, SOCK_DGRAM, 0); struct sockaddr_in dns = {AF_INET, htons(53)}; dns.sin_addr.s_addr = inet_addr("8.8.8.8");
        if (connect(s_ip, (struct sockaddr*)&dns, sizeof(dns)) == 0) {
            struct sockaddr_in name; socklen_t nl = sizeof(name); getsockname(s_ip, (struct sockaddr*)&name, &nl);
            inet_ntop(AF_INET, &name.sin_addr, local_ip, 64);
        } close(s_ip);
    }
    for (int i=0, j=0; local_ip[i]; i++) global_ip_comma[j++] = (local_ip[i] == '.') ? ',' : local_ip[i];

	// Define two permanent listeners
    int l2121 = setup_listener(2121), l2122 = setup_listener(2122), cs = -1; 
    struct pollfd fds[3]; char v_dir[MAX_PATH] = "/", rnf[MAX_PATH] = {0}; struct stat st;
    struct sockaddr_in caddr; socklen_t len = sizeof(caddr);
    printf("===================================================\n");
    printf(" tiny chacha20-poly1309 AEAD (or PLAIN) FTP SERVER \n");
    printf(" URL: ftp://%s@%s@%s:2122 (or :2121)\n",u_key,p_key,local_ip);
    printf("===================================================\n");

    while (1) {
#ifdef AEAD_ONLY
		// Port 2121 is disabled for Plain Command connections
		fds[0].fd = (cs == -1) ? -1 : (data_listener == l2121 ? l2121 : -1);
#else
		fds[0].fd = (cs == -1) ? l2121 : (data_listener == l2121 ? l2121 : -1);
#endif
        fds[1].fd = (cs == -1) ? l2122 : (data_listener == l2122 ? l2122 : -1);
        fds[2].fd = cs; fds[0].events = fds[1].events = fds[2].events = POLLIN;

        if (poll(fds, 3, 60000) <= 0) {
            if (cs != -1) { 
				close(cs); cs = -1; 
				v_dir[1]=0;  // set v_dir = "/"
				printf("[TIMEOUT] Closing Command Channel.\n");
			}
            continue;
        }

        // Non-blocking data channel accept
        if (cs != -1) {
            int d_idx = (data_listener == l2121) ? 0 : 1;
            if (fds[d_idx].revents & POLLIN) {
                struct sockaddr_in da; socklen_t dl = sizeof(da);
                pending_data_fd = accept(data_listener, (struct sockaddr*)&da, &dl);
                if (pending_data_fd != -1 && sec) init_conn_sec(pending_data_fd, &data_ctx);
                continue; 
            }
        }

        // Now these blocks only trigger if we are IDLE
        if (cs == -1 && (fds[0].revents & POLLIN)) {
            sec = 0; 
			//cs = accept(l2121, NULL, NULL); 
            cs = accept(l2121, (struct sockaddr*)&caddr, &len); 
			data_listener = l2122; send_s(cs, "220 Ready\r\n");
        printf("[CONN] Plain Client connected from %s:2121\n", inet_ntoa(caddr.sin_addr));
            continue; 
        } 
        else if (cs == -1 && (fds[1].revents & POLLIN)) {
            sec = 1; 
			// cs = accept(l2122, NULL, NULL); 
            cs = accept(l2122, (struct sockaddr*)&caddr, &len); 
			data_listener = l2121;
            init_conn_sec(cs, &cmd_ctx); send_s(cs, "220 AEAD Secure FTP Ready\r\n"); 
        	printf("[CONN] AEAD Client connected from %s:2122\n", inet_ntoa(caddr.sin_addr));
			continue;
        }

        // Active command socket processing
        if (cs != -1 && (fds[2].revents & POLLIN)) {
            int n = x_recv_ctx(cs, &cmd_ctx);
// 1. Strict Length Validation
    // If the decrypted frame exceeds our buffer, it's a violation.
            if (n <= 0 || n >= (int)sizeof(buf)) { close(cs); cs = -1; continue; 
        // No 500 error, no truncation, no "Proceeding anyway."
        // We just drop the connection, exactly like a MAC failure.
        printf("[ERR] Protocol Violation: Command length = %d bytes. Closing.\n", n);
			}
            
    // 2. Safe, exact copy into the command buffer
            memcpy(buf, cmd_ctx.b.payload, n);
            buf[n] = 0; char *arg = strchr(buf, ' '); if (arg) { arg++; clean_cmd(arg); }
#ifdef DEBUG            
            log_to_file('<',(uint8_t *)buf,(int)strlen(buf));   
#endif            

            int dp = (data_listener == l2121) ? 2121 : 2122;

            if (strncmp(buf, "USER", 4) == 0) { if (strstr(buf, u_key)) send_s(cs, "331 OK\r\n"); else { close(cs); cs = -1; } }
            else if (strncmp(buf, "PASS", 4) == 0) { if (strstr(buf, p_key)) send_s(cs, "230 OK\r\n"); else { close(cs); cs = -1; } }
            else if (strncmp(buf, "PASV", 4) == 0) { char m[128]; sprintf(m, "227 Entering Passive Mode (%s,%d,%d).\r\n", global_ip_comma, dp >> 8, dp & 0xFF); send_s(cs, m); }
            else if (strncmp(buf, "LIST", 4) == 0 || strncmp(buf, "MLSD", 4) == 0) { send_s(cs, "150 OK\r\n"); send_list_data(v_dir, buf[0]=='M'); send_s(cs, "226 Done\r\n"); }
            else if (strncmp(buf, "PWD", 3) == 0 || strncmp(buf, "XPWD", 4) == 0) { char m[MAX_PATH+32]; sprintf(m, "257 \"%s\"\r\n", v_dir); send_s(cs, m); }
            else if (strncmp(buf, "CWD", 3) == 0 && arg) { if (strstr(arg, "..")) send_s(cs, "550 Fail\r\n"); else { if (arg[0] == '/') strcpy(v_dir, arg); else { if (strcmp(v_dir, "/")!=0) strcat(v_dir, "/"); strcat(v_dir, arg); } send_s(cs, "250 OK\r\n"); } }
            else if ((strncmp(buf, "RETR", 4) == 0 || strncmp(buf, "STOR", 4) == 0) && arg) { send_s(cs, "150 OK\r\n"); if (file_op(v_dir, arg, buf[0]=='R')) send_s(cs, "226 Done\r\n"); else send_s(cs, "550 Fail\r\n"); }
            else if (strncmp(buf, "MDTM", 4) == 0 && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if (stat(lp, &st) == 0) { struct tm *tm = gmtime(&st.st_mtime); char m[64]; sprintf(m, "213 %04d%02d%02d%02d%02d%02d\r\n", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec); send_s(cs, m); } else send_s(cs, "550 Fail\r\n"); }
            else if (strncmp(buf, "MFMT", 4) == 0 && arg) { char ts[16], fn[MAX_PATH], lp[MAX_PATH]; sscanf(arg, "%14s %s", ts, fn); get_lp(lp, v_dir, fn); struct tm t = {0}; struct utimbuf ut; sscanf(ts, "%4d%2d%2d%2d%2d%2d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec); t.tm_year -= 1900; t.tm_mon -= 1; ut.actime = ut.modtime = timegm(&t); if (utime(lp, &ut) == 0) { char m[128]; sprintf(m, "213 Modify=%s; %s\r\n", ts, fn); send_s(cs, m); } else send_s(cs, "550 Fail\r\n"); }
            else if (strncmp(buf, "MKD", 3) == 0 && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if (mkdir(lp, 0755) == 0 || errno == EEXIST) send_s(cs, "257 OK\r\n"); else send_s(cs, "550 Fail\r\n"); }
            else if ((strncmp(buf, "DELE", 4) == 0 || strncmp(buf, "RMD", 3) == 0) && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if ((buf[0]=='D' ? unlink(lp) : rmdir(lp)) == 0) send_s(cs, "250 OK\r\n"); else send_s(cs, "550 Fail\r\n"); }
            else if (strncmp(buf, "RNFR", 4) == 0 && arg) { strcpy(rnf, arg); send_s(cs, "350 OK\r\n"); }
            else if (strncmp(buf, "RNTO", 4) == 0 && arg) { char lp1[MAX_PATH], lp2[MAX_PATH]; get_lp(lp1, v_dir, rnf); get_lp(lp2, v_dir, arg); if (rename(lp1, lp2) == 0) send_s(cs, "250 OK\r\n"); else send_s(cs, "550 Fail\r\n"); rnf[0]=0; }
            else if (strncmp(buf, "QUIT", 4) == 0) { send_s(cs, "221 Bye\r\n"); close(cs); cs = -1; }
            else if (strncmp(buf, "FEAT", 4) == 0) send_s(cs, "211-Extensions:\r\n MLSD\r\n MDTM\r\n MFMT\r\n UTF8\r\n211 End\r\n");
            else send_s(cs, "200 OK\r\n");
        }
    } return 0;
}
