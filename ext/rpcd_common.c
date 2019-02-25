/******************************************************************************
 * Copyright (C) 2014-2020 Zhifeng Gong <gozfree@163.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/
#include <liblog.h>
#include <libgevent.h>
#include <libmacro.h>
#include <libhash.h>
#include <libskt.h>
#include <libworkq.h>
#include <librpc.h>
#include "rpcd_common.h"
#include "librpc_stub.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define MAX_UUID_LEN                (21)
static int on_get_connect_list(struct rpc *r, void *arg, int len)
{
#if 0
    void *ptr;
    int num = 0;
    struct iovec *buf = CALLOC(1, struct iovec);
    key_list *tmp, *uuids;
    dict_get_key_list(r->dict_uuid2fd, &uuids);
    for (num = 0, tmp = uuids; tmp; tmp = tmp->next, ++num) {
    }
    uuids = NULL;
    buf->iov_len = num * MAX_UUID_LEN;
    buf->iov_base = calloc(1, buf->iov_len);
    for (ptr = buf->iov_base, tmp = uuids; tmp; tmp = tmp->next, ++num) {
        logi("uuid list: %s\n", (tmp->key));
        len = MAX_UUID_LEN;
        memcpy(ptr, tmp->key, len);
        ptr += len;
    }
    r->send_pkt.header.msg_id = RPC_GET_CONNECT_LIST;
    r->send_pkt.header.payload_len = buf->iov_len;
    logi("rpc_send len = %d, buf = %s\n", buf->iov_len, buf->iov_base);
    rpc_send(r, buf->iov_base, buf->iov_len);
#endif
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
    logi("send len = %d, buf: %s\n", strlen(buf), buf);
    ret = rpc_send(r, buf, strlen(buf));
    loge("ret = %d, errno = %d\n", ret, errno);
    return 0;
}

static int on_peer_post_msg(struct rpc *r, void *arg, int len)
{
    char uuid_src[9];
    char uuid_dst[9];
    snprintf(uuid_src, sizeof(uuid_src), "%x", r->recv_pkt.header.uuid_src);
    snprintf(uuid_dst, sizeof(uuid_dst), "%x", r->recv_pkt.header.uuid_dst);

    logi("post msg from %s to %s\n", uuid_src, uuid_dst);
    char *valfd = (char *)hash_get(r->dict_uuid2fd, uuid_dst);
    if (!valfd) {
        loge("hash_get failed: key=%08x\n", r->send_pkt.header.uuid_dst);
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
