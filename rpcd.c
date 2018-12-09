/*****************************************************************************
 * Copyright (C) 2014-2015
 * file:    rpcd.c
 * author:  gozfree <gozfree@163.com>
 * created: 2015-07-20 00:01
 * updated: 2015-08-02 17:44
 *****************************************************************************/
#include <libmacro.h>
#include <liblog.h>
#include <libgevent.h>
#include <libhash.h>
#include <libskt.h>
#include <libworkq.h>
#include <librpc.h>
#include "rpcd.h"
#include "ext/rpcd_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>


#define MAX_UUID_LEN                (21)
#define RPCD_LISTEN_PORT    12345

struct rpcd *_rpcd;
void rpc_connect_destroy(struct rpcd *rpcd, struct rpc *r);

struct wq_arg {
    msg_handler_t handler;
    struct rpc r;
    void *buf;
    size_t len;

};

static void process_wq(void *arg)
{
    struct wq_arg *wq = (struct wq_arg *)arg;
    if (&wq->handler) {
        wq->handler.cb(&wq->r, wq->buf, wq->len);
    }
}

static int do_process_msg(struct rpc *r, void *buf, size_t len)
{
    char uuid_str[4];
    int ret;
    msg_handler_t *msg_handler;
    struct rpc_header *h = &r->recv_pkt.header;
    int msg_id = rpc_packet_parse(r);
    logi("msg_id = %08x\n", msg_id);

    msg_handler = find_msg_handler(msg_id);
    if (msg_handler) {
        struct wq_arg *arg = CALLOC(1, struct wq_arg);
        memcpy(&arg->handler, msg_handler, sizeof(msg_handler_t));
        memcpy(&arg->r, r, sizeof(struct rpc));
        arg->buf = calloc(1, len);
        memcpy(arg->buf, buf, len);
        arg->len = len;
        wq_task_add(_rpcd->wq, process_wq, arg, sizeof(struct wq_arg));
        //msg_handler->cb(r, buf, len);
    } else {
        loge("no callback for this MSG ID(%d) in process_msg\n", msg_id);
        snprintf(uuid_str, sizeof(uuid_str), "%x", h->uuid_dst);
        char *valfd = (char *)hash_get(_rpcd->dict_uuid2fd, uuid_str);
        if (!valfd) {
            loge("hash_get failed: key=%s\n", h->uuid_dst);
            return -1;
        }
        int dst_fd = strtol(valfd, NULL, 16);
        r->fd = dst_fd;
        ret = rpc_send(r, buf, len);
    }
    return ret;
}

void on_recv(int fd, void *arg)
{
    struct iovec *buf;
    char key[9];
    snprintf(key, sizeof(key), "%08x", fd);
    struct rpc *r = (struct rpc *)hash_get(_rpcd->dict_fd2rpc, key);
    if (!r) {
        loge("hash_get failed: key=%s", key);
        return;
    }
    buf = rpc_recv_buf(r);
    if (!buf) {
        logd("on_disconnect fd = %d\n", r->fd);
        rpc_connect_destroy(_rpcd, r);
        return;
    }
    do_process_msg(r, buf->iov_base, buf->iov_len);
    r->fd = fd;//must be reset
    free(buf->iov_base);
    free(buf);
}

void on_error(int fd, void *arg)
{
    loge("error: %d\n", errno);
}

int create_uuid(char *uuid, int len, int fd, uint32_t ip, uint16_t port)
{
    snprintf(uuid, MAX_UUID_LEN, "%08x%08x%04x", fd, ip, port);
    return 0;
}

int rpcd_connect_add(struct rpcd *rpcd, struct rpc *r, int fd, uint32_t uuid)
{
    char fd_str[9];
    char uuid_str[9];
    char *fdval = (char *)calloc(1, 9);
    snprintf(fd_str, sizeof(fd_str), "%08x", fd);
    snprintf(uuid_str, sizeof(uuid_str), "%08x", uuid);
    snprintf(fdval, 9, "%08x", fd);
    hash_set(rpcd->dict_fd2rpc, fd_str, (char *)r);
    hash_set(rpcd->dict_uuid2fd, uuid_str, fdval);
    logd("add connection fd:%s, uuid:%s\n", fd_str, uuid_str);
    return 0;
}

int rpcd_connect_del(struct rpcd *rpcd, int fd, uint32_t uuid)
{
    char uuid_str[9];
    char fd_str[9];
    snprintf(fd_str, sizeof(fd_str), "%08x", fd);
    snprintf(uuid_str, sizeof(uuid_str), "%08x", uuid);
    hash_del(rpcd->dict_fd2rpc, fd_str);
    hash_del(rpcd->dict_uuid2fd, uuid_str);
    logd("delete connection fd:%s, uuid:%s\n", fd_str, uuid_str);
    return 0;
}

struct rpc *rpc_connect_create(struct rpcd *rpcd,
                int fd, uint32_t ip, uint16_t port)
{
    char str_ip[INET_ADDRSTRLEN];
    char uuid[MAX_UUID_LEN];
    uint32_t uuid_hash;
    int ret;

    struct rpc *r = (struct rpc *)calloc(1, sizeof(struct rpc));
    if (!r) {
        loge("malloc failed!\n");
        return NULL;
    }
    r->fd = fd;
    create_uuid(uuid, MAX_UUID_LEN, fd, ip, port);
    uuid_hash = hash_gen32(uuid, sizeof(uuid));
    struct gevent *e = gevent_create(fd, on_recv, NULL, on_error, (void *)r);
    if (-1 == gevent_add(rpcd->evbase, e)) {
        loge("event_add failed!\n");
    }
    r->ev = e;

    r->send_pkt.header.uuid_src = uuid_hash;
    r->send_pkt.header.uuid_dst = uuid_hash;
    r->send_pkt.header.msg_id = 0;
    r->send_pkt.header.payload_len = sizeof(uuid_hash);
    r->send_pkt.payload = &uuid_hash;
    ret = rpc_send(r, r->send_pkt.payload, r->send_pkt.header.payload_len);
    if (ret == -1) {
        loge("rpc_send failed\n");
    }
    rpcd_connect_add(rpcd, r, fd, uuid_hash);
    skt_addr_ntop(str_ip, ip);
    logd("on_connect fd = %d, remote_addr = %s:%d, uuid=0x%08x\n",
                    fd, str_ip, port, uuid_hash);

    return r;
}

void rpc_connect_destroy(struct rpcd *rpcd, struct rpc *r)
{
    if (!rpcd || !r) {
        loge("invalid paramets!\n");
        return;
    }
    int fd = r->fd;
    uint32_t uuid = r->send_pkt.header.uuid_src;
    struct gevent *e = r->ev;
    rpcd_connect_del(rpcd, fd, uuid);
    gevent_del(rpcd->evbase, e);
}

void on_connect(int fd, void *arg)
{
    int afd;
    uint32_t ip;
    uint16_t port;
    struct rpcd *rpcd = (struct rpcd *)arg;

    afd = skt_accept(fd, &ip, &port);
    if (afd == -1) {
        loge("skt_accept failed: %d\n", errno);
        return;
    }
    rpc_connect_create(rpcd, afd, ip, port);
}

int rpcd_init(uint16_t port)
{
    int fd;
    fd = skt_tcp_bind_listen(NULL, port);
    if (fd == -1) {
        loge("skt_tcp_bind_listen port:%d failed!\n", port);
        return -1;
    }
    if (0 > skt_set_tcp_keepalive(fd, 1)) {
        loge("skt_set_tcp_keepalive failed!\n");
        return -1;
    }
    logi("rpcd listen port = %d\n", port);
    _rpcd = CALLOC(1, struct rpcd);
    _rpcd->listen_fd = fd;
    _rpcd->evbase = gevent_base_create();
    if (!_rpcd->evbase) {
        loge("gevent_base_create failed!\n");
        return -1;
    }
    struct gevent *e = gevent_create(fd, on_connect, NULL, on_error,
                    (void *)_rpcd);
    if (-1 == gevent_add(_rpcd->evbase, e)) {
        loge("event_add failed!\n");
        gevent_destroy(e);
    }
    _rpcd->dict_fd2rpc = hash_create(10240);
    _rpcd->dict_uuid2fd = hash_create(10240);
    _rpcd->wq = wq_create();
    rpcd_group_register();
    return 0;
}

int rpcd_dispatch()
{
    gevent_base_loop(_rpcd->evbase);
    return 0;
}

void rpcd_deinit()
{
    gevent_base_loop_break(_rpcd->evbase);
    gevent_base_destroy(_rpcd->evbase);
    wq_destroy(_rpcd->wq);
}

void usage()
{
    printf("usage: run as daemon: ./rpcd -d\n"
            "      run for debug: ./rpcd\n");
}

void ctrl_c_op(int signo)
{
    skt_close(_rpcd->listen_fd);
    exit(0);
}

int main(int argc, char **argv)
{
    uint16_t port = RPCD_LISTEN_PORT;
    if (argc > 2) {
        usage();
        exit(-1);
    }
    if (argc == 2) {
        if (!strcmp(argv[1], "-d")) {
            daemon(0, 0);
            log_init(LOG_RSYSLOG, "local2");
        } else {
            port = atoi(argv[1]);
        }
    } else {
        log_init(LOG_STDERR, NULL);
    }
    log_set_level(LOG_INFO);
    signal(SIGINT , ctrl_c_op);
    rpcd_init(port);
    rpcd_dispatch();
    rpcd_deinit();
    return 0;
}
