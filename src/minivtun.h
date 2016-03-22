/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __MINIVTUN_H
#define __MINIVTUN_H

#include "library.h"
#ifdef ANDROID
# include <jni.h>
# include <android/log.h>

#define TAG "minivtun"
#define __QUOTE(x)              # x
#define  _QUOTE(x)              __QUOTE(x)

#define LOG(prio, fmt, ...)                                                \
        ((void)__android_log_print(prio, TAG, \
                                           __FILE__ ":[" _QUOTE(__LINE__) "]\t" fmt, ## __VA_ARGS__))

#define LOGD(...) LOG(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) LOG(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) LOG(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) LOG(ANDROID_LOG_ERROR, __VA_ARGS__)
#else
#define LOGD(...) fprintf(stdout, __VA_ARGS__)
#define LOGI(...) fprintf(stdout, __VA_ARGS__)
#define LOGW(...) fprintf(stdout, __VA_ARGS__)
#define LOGE(...) fprintf(stderr, __VA_ARGS__)

#endif

extern struct minivtun_config config;

struct minivtun_config {
	unsigned reconnect_timeo;
	unsigned keepalive_timeo;
	char devname[40];
	unsigned tun_mtu;
	const char *crypto_passwd;
	const char *pid_file;
	bool in_background;
	bool wait_dns;

	char crypto_key[CRYPTO_MAX_KEY_SIZE];
	const void *crypto_type;
	struct in_addr local_tun_in;
	struct in6_addr local_tun_in6;
};

enum {
	MINIVTUN_MSG_KEEPALIVE,
	MINIVTUN_MSG_IPDATA,
	MINIVTUN_MSG_DISCONNECT,
};

#define NM_PI_BUFFER_SIZE  (1024 * 8)

struct minivtun_msg {
	struct {
		__u8 opcode;
		__u8 rsv[3];
		__u8 auth_key[16];
	}  __attribute__((packed)) hdr;

	union {
		struct {
			__be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
			__be16 ip_dlen; /* Total length of IP/IPv6 data */
			char data[NM_PI_BUFFER_SIZE];
		} __attribute__((packed)) ipdata;
		struct {
			struct in_addr loc_tun_in;
			struct in6_addr loc_tun_in6;
		} __attribute__((packed)) keepalive;
	};
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN  (sizeof(((struct minivtun_msg *)0)->hdr))
#define MINIVTUN_MSG_IPDATA_OFFSET  (offsetof(struct minivtun_msg, ipdata.data))

#define enabled_encryption()  (config.crypto_passwd && config.crypto_passwd[0])

static inline void local_to_netmsg(void *in, void **out, size_t *dlen)
{
	if (enabled_encryption()) {
		datagram_encrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
	} else {
		*out = in;
	}
}
static inline void netmsg_to_local(void *in, void **out, size_t *dlen)
{
	if (enabled_encryption()) {
		datagram_decrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
	} else {
		*out = in;
	}
}

#ifdef ANDROID
//int run_client(int tunfd, int sockfd);
#else
int run_client(int tunfd, const char *peer_addr_pair);
#endif
int run_server(int tunfd, const char *loc_addr_pair);
int vt_route_add(struct in_addr *network, unsigned prefix, struct in_addr *gateway);

#endif /* __MINIVTUN_H */

