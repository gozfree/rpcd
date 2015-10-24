/*****************************************************************************
 * Copyright (C) 2014-2015
 * file:    rpcd.c
 * author:  gozfree <gozfree@163.com>
 * created: 2015-07-20 00:01
 * updated: 2015-08-02 17:44
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libglog.h>
#include <libgevent.h>
#include <libdict.h>
#include <libskt.h>
#include <libgzf.h>
#include <libworkq.h>
#include <librpc.h>
#include "rpcd.h"
#include "ext/rpcd_common.h"

#define RPCD_LISTEN_PORT    12345

struct rpcd *_rpcd;
void rpc_connect_destroy(struct rpcd *rpcd, struct rpc *r);

int process_msg(struct rpc *r, struct iobuf *buf)
{
    int ret;
    msg_handler_t msg_handler;
    struct rpc_header *h = &r->packet.header;
    int msg_id = rpc_packet_parse(r);

    if (find_msg_handler(msg_id, &msg_handler) == 0) {
        msg_handler.cb(r, buf->addr, buf->len);
    } else {
        loge("no callback for this MSG ID in process_msg\n");
        char *valfd = (char *)dict_get(_rpcd->dict_uuid2fd, h->uuid_dst, NULL);
        if (!valfd) {
            loge("dict_get failed: key=%s\n", h->uuid_dst);
            return -1;
        }
        int dst_fd = strtol(valfd, NULL, 16);
        r->fd = dst_fd;
        ret = rpc_send(r, buf->addr, buf->len);
    }
    return ret;
}

void on_recv(int fd, void *arg)
{
    struct iobuf *buf;
    char key[9];
    snprintf(key, sizeof(key), "%08x", fd);
    struct rpc *r = (struct rpc *)dict_get(_rpcd->dict_fd2rpc, key, NULL);
    if (!r) {
        loge("dict_get failed: key=%s", key);
        return;
    }
    //logi("on_recv fd = %d dict_get: key=%s, r->fd=%d\n", fd, key, r->fd);
    buf = rpc_recv_buf(r);
    if (!buf) {
        //loge("peer connect closed\n");
        rpc_connect_destroy(_rpcd, r);
        return;
    }
    process_msg(r, buf);
    r->fd = fd;//must be reset
    //dump_buffer(buf->addr, buf->len);
    //dump_packet(&r->packet);

    free(buf->addr);
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

int rpcd_connect_add(struct rpcd *rpcd, struct rpc *r, int fd, char *uuid)
{
    char key[9];
    char *fdval = (char *)calloc(1, 9);
    snprintf(key, sizeof(key), "%08x", fd);
    snprintf(fdval, 9, "%08x", fd);
    dict_add(rpcd->dict_fd2rpc, key, (char *)r);
    dict_add(rpcd->dict_uuid2fd, uuid, fdval);
    return 0;
}

void rpcd_connect_del(struct rpcd *rpcd, int fd, char *uuid)
{
    char key[9];
    snprintf(key, sizeof(key), "%08x", fd);
    dict_del(rpcd->dict_fd2rpc, key);
    dict_del(rpcd->dict_uuid2fd, uuid);
}

struct rpc *rpc_connect_create(struct rpcd *rpcd, int fd, uint32_t ip, uint16_t port)
{
    char str_ip[INET_ADDRSTRLEN];
    char uuid[MAX_UUID_LEN];
    int ret;

    struct rpc *r = (struct rpc *)calloc(1, sizeof(struct rpc));
    if (!r) {
        loge("malloc failed!\n");
        return NULL;
    }
    r->fd = fd;
    create_uuid(uuid, MAX_UUID_LEN, fd, ip, port);
    struct gevent *e = gevent_create(fd, on_recv, NULL, on_error, (void *)r);
    if (-1 == gevent_add(rpcd->evbase, e)) {
        loge("event_add failed!\n");
    }
    r->ev = e;
    rpc_header_format(r, uuid, uuid, 0, 0);
    ret = rpc_send(r, uuid, MAX_UUID_LEN);
    if (ret != MAX_UUID_LEN) {
        loge("rpc_send failed!\n");
    }
    rpcd_connect_add(rpcd, r, fd, uuid);
    skt_addr_ntop(str_ip, ip);
    logi("on_connect fd = %d, remote_addr = %s:%d, uuid=%s\n", fd, str_ip, port, uuid);

    return r;
}

void rpc_connect_destroy(struct rpcd *rpcd, struct rpc *r)
{
    if (!rpcd || !r) {
        return;
    }
    int fd = r->fd;
    char *uuid = r->packet.header.uuid_src;
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
    fd = skt_tcp_bind_listen(NULL, port, 0);
    if (fd == -1) {
        return -1;
    }
    logi("rpcd listen port = %d\n", port);
    _rpcd = CALLOC(1, struct rpcd);
    _rpcd->listen_fd = fd;
    _rpcd->evbase = gevent_base_create();
    if (!_rpcd->evbase) {
        return -1;
    }
    struct gevent *e = gevent_create(fd, on_connect, NULL, on_error, (void *)_rpcd);
    if (-1 == gevent_add(_rpcd->evbase, e)) {
        loge("event_add failed!\n");
        gevent_destroy(e);
    }
    _rpcd->dict_fd2rpc = dict_new();
    _rpcd->dict_uuid2fd = dict_new();
    wq_pool_init();
    //REGISTER_MSG_MAP(BASIC_RPC_API);
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
