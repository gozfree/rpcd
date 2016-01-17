/*****************************************************************************
 * Copyright (C) 2014-2015
 * file:    rpcd_common.c
 * author:  gozfree <gozfree@163.com>
 * created: 2015-08-02 00:25
 * updated: 2015-08-02 00:25
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
#include <libgzf.h>
#include <liblog.h>
#include <libosal.h>
#include <libgevent.h>
#include <libdict.h>
#include <libskt.h>
#include <libworkq.h>
#include <librpc.h>
#include "rpcd_common.h"
#include "rpcd.h"
#include "librpc_stub.h"

#define MAX_UUID_LEN                (21)
extern struct rpcd *_rpcd;
static int on_get_connect_list(struct rpc *r, void *arg, int len)
{
    void *ptr;
    int num = 0;
    struct iobuf *buf = CALLOC(1, struct iobuf);
    key_list *tmp, *uuids;
    dict_get_key_list(_rpcd->dict_uuid2fd, &uuids);
    for (num = 0, tmp = uuids; tmp; tmp = tmp->next, ++num) {
    }
    buf->len = num * MAX_UUID_LEN;
    buf->addr = calloc(1, buf->len);
    for (ptr = buf->addr, tmp = uuids; tmp; tmp = tmp->next, ++num) {
        logi("uuid list: %s\n", (tmp->key));
        len = MAX_UUID_LEN;
        memcpy(ptr, tmp->key, len);
        ptr += len;
    }
    r->send_pkt.header.msg_id = RPC_GET_CONNECT_LIST;
    r->send_pkt.header.payload_len = buf->len;
    logi("rpc_send len = %d, buf = %s\n", buf->len, buf->addr);
    rpc_send(r, buf->addr, buf->len);
    return 0;
}

static int on_test(struct rpc *r, void *arg, int len)
{
    logi("on_test\n");
    return 0;
}

static int on_shell_help(struct rpc *r, void *arg, int len)
{
    int ret;
    char buf[1024];
    char *cmd = (char *)arg;
    logi("on_shell_help cmd = %s\n", cmd);
    memset(buf, 0, sizeof(buf));
    ret = system_with_result(cmd, buf, sizeof(buf));
    loge("ret = %d, errno = %d\n", ret, errno);
    logi("send len = %d, buf: %s\n", strlen(buf), buf);
    rpc_send(r, buf, strlen(buf));
    return 0;
}

static int on_peer_post_msg(struct rpc *r, void *arg, int len)
{
    char uuid_src[9];
    char uuid_dst[9];
    snprintf(uuid_src, sizeof(uuid_src), "%x", r->recv_pkt.header.uuid_src);
    snprintf(uuid_dst, sizeof(uuid_dst), "%x", r->recv_pkt.header.uuid_dst);

    logi("post msg from %s to %s\n", uuid_src, uuid_dst);
    char *valfd = (char *)dict_get(_rpcd->dict_uuid2fd, uuid_dst, NULL);
    if (!valfd) {
        loge("dict_get failed: key=%08x\n", r->send_pkt.header.uuid_dst);
        return -1;
    }
    int dst_fd = strtol(valfd, NULL, 16);
    //printf("dst_fd = %d\n", dst_fd);
    r->fd = dst_fd;
    r->send_pkt.header.msg_id = RPC_PEER_POST_MSG;
    return rpc_send(r, arg, len);
}

BEGIN_RPC_MAP(BASIC_RPC_API)
RPC_MAP(RPC_TEST, on_test)
RPC_MAP(RPC_GET_CONNECT_LIST, on_get_connect_list)
RPC_MAP(RPC_PEER_POST_MSG, on_peer_post_msg)
RPC_MAP(RPC_SHELL_HELP, on_shell_help)
END_RPC_MAP()

int rpcd_group_register()
{
    RPC_REGISTER_MSG_MAP(BASIC_RPC_API);
    return 0;
}
