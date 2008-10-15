/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
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

/* param parser */
#include "param_parser.h"

/* this */
#include "mod_parp.h"

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(parp, PARP, apr_status_t, hp_hook,
                                    (request_rec *r, parp_t *p),
                                    (r, p),
                                    OK, DECLINED)

static int parp_header_parser(request_rec * r) {
  //apr_status_t rv = parp_run_hp_hook(r, NULL);
  return DECLINED;
}

static void *parp_srv_config_create(apr_pool_t *p, server_rec *s) {
  return NULL;
}

static void *parp_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return addv;
}

static const command_rec parp_config_cmds[] = {
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void parp_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", NULL };
  ap_hook_header_parser(parp_header_parser, pre, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                     /**< dir config creater */
  NULL,                                     /**< dir merger */
  parp_srv_config_create,                   /**< server config */
  parp_srv_config_merge,                    /**< server merger */
  parp_config_cmds,                         /**< command table */
  parp_register_hooks,                      /**< hook registery */
};
