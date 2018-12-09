/*****************************************************************************
 * Copyright (C) 2014-2015
 * file:    rpcd.h
 * author:  gozfree <gozfree@163.com>
 * created: 2015-07-22 01:11
 * updated: 2015-07-22 01:11
 *****************************************************************************/
#ifndef _RPCD_H_
#define _RPCD_H_

#include <libhash.h>
#include <libmacro.h>
#include <libdict.h>
#include <libgevent.h>
#include <libworkq.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct rpcd {
    int listen_fd;
    struct gevent_base *evbase;
    struct hash *dict_uuid2fd;
    struct hash *dict_fd2rpc;
    struct workq *wq;

} rpcd_t;

#ifdef __cplusplus
}
#endif
#endif
