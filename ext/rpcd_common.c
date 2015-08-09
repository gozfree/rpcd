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
#include <liblog.h>
#include <libgevent.h>
#include <libdict.h>
#include <libskt.h>
#include <libgzf.h>
#include <libworkq.h>
#include <librpc.h>
#include "rpcd_common.h"
#include "rpcd.h"
extern struct rpcd *_rpcd;
static int on_get_connect_list(struct rpc *r, void *arg, int len)
{
    void *ptr;
    int num = 0;
    struct iobuf *buf = CALLOC(1, struct iobuf);
    key_list *tmp, *uuids;
    logi("on_get_connect_list, len = %d\n", len);
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
    rpc_send(r, buf->addr, buf->len);
    return 0;
}

static int on_test(struct rpc *r, void *arg, int len)
{
    logi("on_test\n");
    return 0;
}

static int on_peer_post_msg(struct rpc *r, void *arg, int len)
{
    char *valfd = (char *)dict_get(_rpcd->dict_uuid2fd, r->packet.header.uuid_dst, NULL);
    if (!valfd) {
        loge("dict_get failed: key=%s\n", r->packet.header.uuid_dst);
        return -1;
    }
    int dst_fd = strtol(valfd, NULL, 16);
    //printf("dst_fd = %d\n", dst_fd);
    r->fd = dst_fd;
    return rpc_send(r, arg, len);
}

BEGIN_MSG_MAP(BASIC_RPC_API)
MSG_ACTION(RPC_TEST, on_test)
MSG_ACTION(RPC_GET_CONNECT_LIST, on_get_connect_list)
MSG_ACTION(RPC_PEER_POST_MSG, on_peer_post_msg)
END_MSG_MAP()

int rpcd_group_register()
{
    REGISTER_MSG_MAP(BASIC_RPC_API);
    return 0;
}
