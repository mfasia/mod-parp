/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*  ____  _____  ____ ____  
 * |H _ \(____ |/ ___)  _ \ 
 * |T|_| / ___ | |   | |_| |
 * |T __/\_____|_|   |  __/ 
 * |P|ParameterParser|_|    
 * http://parp.sourceforge.net
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id$";
static const char g_revision[] = "0.1";

/************************************************************************
 * Includes
 ***********************************************************************/
/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_request.h>
#include <http_config.h>
#include <http_log.h>

/* apr */
#include <apr_hooks.h>

/* param parser module */
#include "mod_parp.h"

static apr_status_t parp_appl_test(request_rec * r, apr_table_t *table) {
  return DECLINED;
}

static int parp_appl_post_read_request(request_rec * r) {
  return DECLINED;
}

static void *parp_appl_srv_config_create(apr_pool_t *p, server_rec *s) {
  return NULL;
}

static void *parp_appl_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return addv;
}

static const command_rec parp_appl_config_cmds[] = {
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void parp_appl_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", NULL };
  ap_hook_post_read_request(parp_appl_post_read_request, pre, NULL, APR_HOOK_LAST);
  APR_OPTIONAL_HOOK(parp, hp_hook, parp_appl_test, NULL, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_appl_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                     /**< dir config creater */
  NULL,                                     /**< dir merger */
  parp_appl_srv_config_create,              /**< server config */
  parp_appl_srv_config_merge,               /**< server merger */
  parp_appl_config_cmds,                    /**< command table */
  parp_appl_register_hooks,                 /**< hook registery */
};
