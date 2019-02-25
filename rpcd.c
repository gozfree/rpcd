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
#include <libmacro.h>
#include <liblog.h>
#include <libgevent.h>
#include <libhash.h>
#include <libskt.h>
#include <libworkq.h>
#include <librpc.h>
#include "ext/rpcd_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define RPCD_LISTEN_PORT    12345

static struct rpc *g_rpcd = NULL;
static bool g_run = false;

int rpcd_init(uint16_t port)
{
    g_rpcd = rpc_server_create(NULL, port);
    if (g_rpcd == NULL) {
        loge("rpc_server_create failed!\n");
        return -1;
    }
    rpcd_group_register();
    return 0;
}

int rpcd_dispatch()
{
    g_run = true;
    while (g_run) {
        sleep(1);
    }
    return 0;
}

void rpcd_deinit()
{
    rpc_destroy(g_rpcd);
}

void usage()
{
    printf("usage: run as daemon: ./rpcd -d\n"
            "      run for debug: ./rpcd\n");
}

void ctrl_c_op(int signo)
{
    g_run = false;
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
