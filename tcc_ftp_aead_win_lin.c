/*
 * Universal Portable AEAD FTP Server (Windows & Linux)
 * Features: UTF-8 Unicode Support, AEAD Security, Cross-Platform Socket Logic
 * Build (Win): tcc ftp_aead.c -lws2_32 -ladvapi32 -o ftp_aead.exe
 * Build (Lin): tcc -o ftp_aead ftp_aead.c
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

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#ifdef _WIN32
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <direct.h>
 #include <io.h>
 #include <sys/utime.h>
 #define strcasecmp _stricmp
 #define timegm _mkgmtime
 #define utimbuf _utimbuf
 #define socket_close closesocket
 typedef int socklen_t;
 #ifndef POLLIN
 typedef struct pollfd { SOCKET fd; short events; short revents; } WSAPOLLFD;
 #define POLLIN 0x0300
 WINSOCK_API_LINKAGE int WSAAPI WSAPoll(WSAPOLLFD* fds, ULONG nfds, INT timeout);
 #endif
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <sys/prctl.h>
 #include <signal.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <dirent.h>
 #include <utime.h>
 #include <poll.h>
 #define socket_close close
 #define SOCKET int
 #define INVALID_SOCKET -1
 #define SOCKET_ERROR -1
#endif

// BearSSL core source
#include "CORE_CRYPTOGRAPHIC_ENGINE.c"

#define BUF_SIZE 8192
#ifndef MAX_PATH
 #define MAX_PATH 4096
#endif

//#define AEAD_ONLY

/* !!! CHANGE THIS KEY BEFORE COMPILING !!! */
static const uint8_t global_key[32] = { [0 ... 31] = 0x42 };
static const char u_key[] = "vpn"; 
static const char p_key[] = "vpn";

// AEAD CONTEXTS
typedef struct {
 uint8_t key[32];
 uint8_t ctx_nonce[12];
 union {
 uint8_t raw[BUF_SIZE];
 struct { uint32_t len_le; uint8_t nonce[12]; uint8_t payload[BUF_SIZE - 32]; uint8_t tag[16]; };
 } b;
} bc_ctx;

static bc_ctx cmd_ctx, data_ctx;
static int sec = 0;
static SOCKET pending_data_fd = INVALID_SOCKET, data_listener = INVALID_SOCKET;
char global_ip_comma[64] = "127,0,0,1";
static char root_dir[MAX_PATH], buf[BUF_SIZE];

// UNICODE SHIMS
#ifdef _WIN32
static wchar_t g_wbuf[MAX_PATH];
static wchar_t* to_w(const char* utf8) {
 if (utf8 && MultiByteToWideChar(CP_UTF8, 0, utf8, -1, g_wbuf, MAX_PATH)) {
 for (wchar_t *p = g_wbuf; *p; p++) if (*p == L'/') *p = L'\\'; return g_wbuf;
 } return NULL;
}

struct dirent { char d_name[MAX_PATH]; };
typedef struct { HANDLE h; WIN32_FIND_DATAW data; struct dirent ent; int first; } DIR;
static DIR d;

DIR* opendir(const char* path) {
 char search[MAX_PATH];
 sprintf(search, "%s\\*", path);
 d.h = FindFirstFileW(to_w(search), &d.data);
 if (d.h == INVALID_HANDLE_VALUE) return NULL;
 d.first = 1;
 return &d;
}

struct dirent* readdir(DIR* d_ptr) {
 if (!d_ptr->first && !FindNextFileW(d_ptr->h, &d_ptr->data)) return NULL;
 d_ptr->first = 0;
 WideCharToMultiByte(CP_UTF8, 0, d_ptr->data.cFileName, -1, d_ptr->ent.d_name, MAX_PATH, NULL, NULL);
 return &d_ptr->ent;
}

void closedir(DIR* d_ptr) {
 if (d_ptr && d_ptr->h != INVALID_HANDLE_VALUE) { FindClose(d_ptr->h); d_ptr->h = INVALID_HANDLE_VALUE; }
}


 #define x_stat(p, s) _wstat(to_w(p), s)
 #define x_mkdir(p) _wmkdir(to_w(p))
 #define x_remove(p) _wremove(to_w(p))
 #define x_rmdir(p) _wrmdir(to_w(p))
static int x_rename(const char* o, const char* n) {
 wchar_t w[MAX_PATH], *t;
 return ((t = to_w(o)) && wcscpy(w, t) && (t = to_w(n))) ? _wrename(w, t) : -1;
}
#define x_fopen(p, m) _wfopen(to_w(p), ((m)[0] == 'r') ? L"rb" : L"wb")
#else
 #define x_stat stat
 #define x_mkdir(p) mkdir(p, 0755)
 #define x_remove remove
 #define x_rmdir rmdir
 #define x_rename rename
 #define x_fopen fopen
#endif

void inc_nonce(uint8_t *n) { for(int i = 0; i < 12; i++) if(++n[i] != 0) break; }

void init_conn_sec(SOCKET fd, bc_ctx *ctx) {
#ifdef _WIN32
 HCRYPTPROV hP;
 if (CryptAcquireContext(&hP, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
 CryptGenRandom(hP, 12, ctx->ctx_nonce);
 CryptReleaseContext(hP, 0);
 } else { uint32_t t = GetTickCount(); memcpy(ctx->ctx_nonce, &t, 4); }
#else
 int rfd = open("/dev/urandom", O_RDONLY);
 if (rfd >= 0) { read(rfd, ctx->ctx_nonce, 12); close(rfd); }
#endif
 send(fd, (char*)ctx->ctx_nonce, 12, 0);
 memcpy(ctx->key, global_key, 32);
}

void x_send_ctx(SOCKET fd, int len, bc_ctx *ctx) {
 if (sec) {
 memcpy(ctx->b.nonce, ctx->ctx_nonce, 12);
 br_enc32le(&ctx->b.len_le, (uint32_t)len);
 br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, len, ctx->b.raw, 16, ctx->b.payload + len, br_chacha20_ct_run, 1);
 send(fd, (char*)ctx->b.raw, 16 + len + 16, 0);
 inc_nonce(ctx->ctx_nonce);
 } else send(fd, (char*)ctx->b.payload, len, 0);
}

int x_recv_ctx(SOCKET fd, bc_ctx *ctx) {
 if (sec) {
 if (recv(fd, (char*)ctx->b.raw, 16, MSG_WAITALL) <= 0) return -1;
 uint32_t len = br_dec32le(&ctx->b.len_le);
 if (len > (BUF_SIZE - 32)) return -1;
 if (recv(fd, (char*)ctx->b.payload, len + 16, MSG_WAITALL) <= 0) return -1;
 uint8_t tag[16];
 br_poly1305_ctmul_run(ctx->key, ctx->b.nonce, ctx->b.payload, len, ctx->b.raw, 16, tag, br_chacha20_ct_run, 0);
 if (memcmp(tag, ctx->b.payload + len, 16) != 0) return -1;
 inc_nonce(ctx->ctx_nonce);
 return (int)len;
 }
 return recv(fd, (char*)ctx->b.payload, BUF_SIZE - 32, 0);
}

void send_s(SOCKET s, const char* msg) { int l = (int)strlen(msg); memcpy(cmd_ctx.b.payload, msg, l); x_send_ctx(s, l, &cmd_ctx); }
void clean_cmd(char* t) { for(int i=0; t[i]; i++) if(t[i]=='\r' || t[i]=='\n') t[i] = 0; }
int get_lp(char* lp, const char* cur, const char* fn) {
 return (fn && *fn && !strstr(fn, "..") && (strlen(root_dir) + (fn[0] == '/' ? 0 : (cur[1] ? strlen(cur) : 0)) + strlen(fn) + 2 <= MAX_PATH))
 ? (fn[0] == '/' ? sprintf(lp, "%s/%s", root_dir, fn + 1) : sprintf(lp, "%s%s/%s", root_dir, cur[1] ? cur : "", fn))
 : (!fn || !*fn) ? sprintf(lp, "%s%s", root_dir, cur[1] ? cur : "") : 0;
}


void send_list_data(const char* v_path, int is_mlsd) {
 SOCKET cl = pending_data_fd; 
 pending_data_fd = INVALID_SOCKET;
 
 if (cl == INVALID_SOCKET) {
 cl = accept(data_listener, NULL, NULL);
 if (cl != INVALID_SOCKET && sec) init_conn_sec(cl, &data_ctx);
 }

 if (cl != INVALID_SOCKET) {
 char lp[MAX_PATH]; 
 get_lp(lp, v_path, NULL); 
 DIR *dir_h = opendir(lp);
 if (dir_h) {
 struct dirent *dir; 
 struct stat st; 
 char fpath[MAX_PATH];
 const char* mos[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

 while ((dir = readdir(dir_h)) != NULL) {
 if (dir->d_name[0] == '.') continue;
 sprintf(fpath, "%s/%s", lp, dir->d_name);
 if (x_stat(fpath, &st) == 0) {
 struct tm *tm = gmtime(&st.st_mtime);
 char *out = (char*)data_ctx.b.payload;
 int l;

 if (is_mlsd) {
 l = sprintf(out, "modify=%04d%02d%02d%02d%02d%02d;type=%s;size=%lld; %s\r\n", 
 tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, 
 tm->tm_hour, tm->tm_min, tm->tm_sec, 
 S_ISDIR(st.st_mode)?"dir":"file", (long long)st.st_size, dir->d_name);
 } else {
 l = sprintf(out, "%crwxr-xr-x 1 ftp ftp %lld %s %02d %02d:%02d %s\r\n", 
 S_ISDIR(st.st_mode)?'d':'-', (long long)st.st_size, 
 mos[tm->tm_mon], tm->tm_mday, tm->tm_hour, tm->tm_min, dir->d_name);
 }
 x_send_ctx(cl, l, &data_ctx);
 }
 }
 closedir(dir_h);
 }
 socket_close(cl);
 }
}
int file_op(const char* v_path, const char* fn, int is_retr) {
 SOCKET cl = pending_data_fd; pending_data_fd = INVALID_SOCKET;
 if (cl == INVALID_SOCKET) { cl = accept(data_listener, NULL, NULL); if (cl != INVALID_SOCKET && sec) init_conn_sec(cl, &data_ctx); }
 if (cl == INVALID_SOCKET) return 0;
 char lp[MAX_PATH]; get_lp(lp, v_path, fn);
 FILE* f = x_fopen(lp, is_retr ? "rb" : "wb");
 if (!f) { socket_close(cl); return 0; }
 int n;
 if (is_retr) { while ((n = (int)fread(data_ctx.b.payload, 1, BUF_SIZE-32, f)) > 0) x_send_ctx(cl, n, &data_ctx); }
 else { while ((n = x_recv_ctx(cl, &data_ctx)) > 0) fwrite(data_ctx.b.payload, 1, n, f); }
 fclose(f); socket_close(cl); return 1;
}

SOCKET setup_listener(int port) {
 SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
 int opt = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
 struct sockaddr_in addr = {AF_INET, htons(port)}; addr.sin_addr.s_addr = INADDR_ANY;
 if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) exit(1);
 listen(ls, 1); return ls;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
 WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
 HMODULE hK32 = GetModuleHandleA("kernel32.dll");
 if (hK32) {
 typedef HANDLE (WINAPI *P_CJO)(LPSECURITY_ATTRIBUTES, LPCSTR);
 typedef BOOL (WINAPI *P_SIJO)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
 typedef BOOL (WINAPI *P_APJO)(HANDLE, HANDLE);
 P_CJO pCJO = (P_CJO)GetProcAddress(hK32, "CreateJobObjectA");
 P_SIJO pSIJO = (P_SIJO)GetProcAddress(hK32, "SetInformationJobObject");
 P_APJO pAPJO = (P_APJO)GetProcAddress(hK32, "AssignProcessToJobObject");
 if (pCJO && pSIJO && pAPJO) {
 HANDLE hJob = pCJO(NULL, NULL);
 JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
 jeli.BasicLimitInformation.LimitFlags = 0x2000;
 pSIJO(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
 pAPJO(hJob, GetCurrentProcess());
 }
 }
#else
 if (!isatty(STDIN_FILENO)) { snprintf(buf, sizeof(buf), "x-terminal-emulator -e '%s' &", argv[0]); system(buf); return 0; }
 prctl(PR_SET_PDEATHSIG, SIGHUP); signal(SIGPIPE, SIG_IGN);
#endif
// char *target = (argc > 1) ? argv[1] : ".";
 char *target = (argc > 1) ? argv[1] : (
#ifdef _WIN32
 "C:/"
#else
 getenv("HOME")
#endif
 );
#ifdef _WIN32
 _wchdir(to_w(target)); _wgetcwd(g_wbuf, MAX_PATH); 
 WideCharToMultiByte(CP_UTF8, 0, g_wbuf, -1, root_dir, MAX_PATH, NULL, NULL);
#else
 chdir(target); getcwd(root_dir, MAX_PATH);
#endif

 char local_ip[64] = "127.0.0.1";
 SOCKET s_ip = socket(AF_INET, SOCK_DGRAM, 0);
 struct sockaddr_in dns = {AF_INET, htons(53)}; dns.sin_addr.s_addr = inet_addr("8.8.8.8");
 if (argc > 2) strncpy(local_ip, argv[2], 63);
 else { if (connect(s_ip, (struct sockaddr*)&dns, sizeof(dns)) == 0) { struct sockaddr_in name; socklen_t nl = sizeof(name); getsockname(s_ip, (struct sockaddr*)&name, &nl); strcpy(local_ip, inet_ntoa(name.sin_addr)); } socket_close(s_ip); }
 for (int i=0, j=0; local_ip[i]; i++) global_ip_comma[j++] = (local_ip[i] == '.') ? ',' : local_ip[i];

 SOCKET l2121 = setup_listener(2121), l2122 = setup_listener(2122), cs = INVALID_SOCKET;
 char v_dir[MAX_PATH] = "/", rnf[MAX_PATH] = {0};
 
 printf("FTP Server. Root: %s\n", root_dir);
 printf("AEAD : ftp://%s:%s@%s:2122\n",u_key,p_key, local_ip);
#ifndef AEAD_ONLY
 printf("PLAIN: ftp://%s:%s@%s:2121\n",u_key,p_key, local_ip);
#endif

 while (1) {
#ifdef _WIN32
 WSAPOLLFD fds[3];
#else
 struct pollfd fds[3];
#endif
 struct stat st;

#ifdef AEAD_ONLY
 // Port 2121 is disabled for Plain Command connections
 fds[0].fd = (cs == INVALID_SOCKET) ? INVALID_SOCKET : (data_listener == l2121 ? l2121 : INVALID_SOCKET);
#else
 fds[0].fd = (cs == INVALID_SOCKET) ? l2121 : (data_listener == l2121 ? l2121 : INVALID_SOCKET);
#endif
 fds[1].fd = (cs == INVALID_SOCKET) ? l2122 : (data_listener == l2122 ? l2122 : INVALID_SOCKET);
 fds[2].fd = cs;
 for(int i=0; i<3; i++) { fds[i].events = POLLIN; fds[i].revents = 0; }

#ifdef _WIN32
 if (WSAPoll(fds, 3, 5000) <= 0)
#else
 if (poll(fds, 3, 5000) <= 0)
#endif
 { if (cs != INVALID_SOCKET) { socket_close(cs); cs = INVALID_SOCKET; v_dir[1]=0; } 
 printf("connection closed...\r"); fflush(stdout);
 continue; }

 if (cs != INVALID_SOCKET && (fds[(data_listener == l2121) ? 0 : 1].revents & POLLIN)) {
 pending_data_fd = accept(data_listener, NULL, NULL);
 if (pending_data_fd != INVALID_SOCKET && sec) init_conn_sec(pending_data_fd, &data_ctx);
 continue;
 }

 if (cs == INVALID_SOCKET && (fds[0].revents & POLLIN)) {
 printf("Plain connection....\r"); fflush(stdout);
 sec = 0; cs = accept(l2121, NULL, NULL);
 data_listener = l2122; send_s(cs, "220 Ready\r\n"); continue;
 } 
 else if (cs == INVALID_SOCKET && (fds[1].revents & POLLIN)) {
 printf("AEAD connection.....\r"); fflush(stdout);
 sec = 1; cs = accept(l2122, NULL, NULL);
 data_listener = l2121; init_conn_sec(cs, &cmd_ctx);
 send_s(cs, "220 AEAD Secure Ready\r\n"); continue;
 }

 if (cs != INVALID_SOCKET && (fds[2].revents & POLLIN)) {
 int n = x_recv_ctx(cs, &cmd_ctx);
 if (n <= 0 || n >= BUF_SIZE) { socket_close(cs); cs = INVALID_SOCKET; continue; }
 memcpy(buf, cmd_ctx.b.payload, n); buf[n] = 0;
 char *arg = strchr(buf, ' '); if (arg) { arg++; clean_cmd(arg); }
 int dp = (data_listener == l2121) ? 2121 : 2122;

 if (strncmp(buf, "USER", 4) == 0) { if (strstr(buf, u_key)) send_s(cs, "331 OK\r\n"); else { socket_close(cs); cs = INVALID_SOCKET; } }
 else if (strncmp(buf, "PASS", 4) == 0) { if (strstr(buf, p_key)) send_s(cs, "230 OK\r\n"); else { socket_close(cs); cs = INVALID_SOCKET; } }
 else if (strncmp(buf, "PASV", 4) == 0) { char m[128]; sprintf(m, "227 Entering Passive Mode (%s,%d,%d).\r\n", global_ip_comma, dp >> 8, dp & 0xFF); send_s(cs, m); }
 else if (strncmp(buf, "LIST", 4) == 0 || strncmp(buf, "MLSD", 4) == 0) { send_s(cs, "150 OK\r\n"); send_list_data(v_dir, buf[0]=='M'); send_s(cs, "226 Done\r\n"); }
 else if (strncmp(buf, "PWD", 3) == 0 || strncmp(buf, "XPWD", 4) == 0) { char m[MAX_PATH+32]; sprintf(m, "257 \"%s\"\r\n", v_dir); send_s(cs, m); }
else if (strncmp(buf, "CWD", 3) == 0 && arg && !strstr(arg, "..")) { char lp[MAX_PATH], *p; struct stat st; if (get_lp(lp, v_dir, arg) && x_stat(lp, &st) == 0 && S_ISDIR(st.st_mode)) { if (arg[0] == '/') strcpy(v_dir, arg); else { p = v_dir + strlen(v_dir); if (p[-1] != '/') *p++ = '/'; strcpy(p, arg); } send_s(cs, "250 OK\r\n"); } else send_s(cs, "550 Fail\r\n"); }
else if ((strncmp(buf, "RETR", 4) == 0 || strncmp(buf, "STOR", 4) == 0) && arg) { send_s(cs, "150 OK\r\n"); if (file_op(v_dir, arg, buf[0]=='R')) send_s(cs, "226 Done\r\n"); else send_s(cs, "550 Fail\r\n"); }
 else if (strncmp(buf, "MDTM", 4) == 0 && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if (x_stat(lp, &st) == 0) { struct tm *tm = gmtime(&st.st_mtime); char m[64]; sprintf(m, "213 %04d%02d%02d%02d%02d%02d\r\n", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec); send_s(cs, m); } else send_s(cs, "550 Fail\r\n"); }
 else if (strncmp(buf, "MFMT", 4) == 0 && arg) { char ts[16], fn[MAX_PATH], lp[MAX_PATH]; if (sscanf(arg, "%14s %s", ts, fn) == 2) { get_lp(lp, v_dir, fn); struct tm t = {0}; struct utimbuf ut; sscanf(ts, "%4d%2d%2d%2d%2d%2d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec); t.tm_year -= 1900; t.tm_mon -= 1; ut.actime = ut.modtime = timegm(&t); if (utime(lp, &ut) == 0) { char m[128]; sprintf(m, "213 Modify=%s; %s\r\n", ts, fn); send_s(cs, m); } else send_s(cs, "550 Fail\r\n"); } else send_s(cs, "501 Syntax\r\n"); }
 else if (strncmp(buf, "MKD", 3) == 0 && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if (x_mkdir(lp) == 0 || errno == EEXIST) send_s(cs, "257 OK\r\n"); else send_s(cs, "550 Fail\r\n"); }
 else if ((strncmp(buf, "DELE", 4) == 0 || strncmp(buf, "RMD", 3) == 0) && arg) { char lp[MAX_PATH]; get_lp(lp, v_dir, arg); if ((buf[0]=='D' ? x_remove(lp) : x_rmdir(lp)) == 0) send_s(cs, "250 OK\r\n"); else send_s(cs, "550 Fail\r\n"); }
else if (strncmp(buf, "RNFR", 4) == 0 && arg) { strcpy(rnf, arg); send_s(cs, "350 OK\r\n"); }
else if (strncmp(buf, "RNTO", 4) == 0 && arg) { char lp1[MAX_PATH], lp2[MAX_PATH]; if (rnf[0] && get_lp(lp1, v_dir, rnf) && get_lp(lp2, v_dir, arg) && x_rename(lp1, lp2) == 0) send_s(cs, "250 OK\r\n"); else send_s(cs, "550 Fail\r\n"); rnf[0] = 0; }
 else if (strncmp(buf, "QUIT", 4) == 0) { send_s(cs, "221 Bye\r\n"); socket_close(cs); cs = INVALID_SOCKET; }
 else if (strncmp(buf, "FEAT", 4) == 0) send_s(cs, "211-Extensions:\r\n MLSD\r\n MDTM\r\n MFMT\r\n UTF8\r\n211 End\r\n");
 else if (strncmp(buf, "OPTS", 4) == 0 && strstr(buf, "UTF8")) send_s(cs, "200 UTF8 OPTS ON\r\n");
 else if (strncmp(buf, "TYPE", 4) == 0) send_s(cs, "200 I\r\n");
 else send_s(cs, "200 OK\r\n");
 }
 }
}
