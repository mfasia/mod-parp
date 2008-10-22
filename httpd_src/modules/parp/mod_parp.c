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
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>

/* param parser */
#include "param_parser.h"

/* this */
#include "mod_parp.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define PARP_LOG_PFX(id)  "mod_parp("#id"): "

/************************************************************************
 * structures
 ***********************************************************************/
/**
 * server configuration
 */
typedef struct {
  int onerror;
} parp_srv_config;


/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_module;

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(parp, PARP, apr_status_t, hp_hook,
                                    (request_rec *r, apr_table_t *table),
                                    (r, table),
                                    OK, DECLINED)

/************************************************************************
 * functions
 ***********************************************************************/
static apr_table_t *parp_hp_table(request_rec *r) {
  parp_t *parp = ap_get_module_config(r->request_config, &parp_module);
  apr_table_t *tl = NULL;
  if(parp) {
    parp_get_params(parp, &tl);
  }
  return tl;
}  

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Header parser starts body parsing when reading "parp" in
 * the process environment or request notes and calls all
 * functions  registered to the hs_hook.
 *
 * @param r IN request record
 * @return DECLINED if inactive, return code of the registered
 *         functions or the value defined by PARP_ExitOnError
 *         on any parser error.
 */
static int parp_header_parser(request_rec * r) {
  apr_status_t status = DECLINED;
  const char *e = apr_table_get(r->notes, "parp");
  if(e == NULL) {
    e = apr_table_get(r->subprocess_env, "parp");
  }
  if(e == NULL) {
    /* no event */
    return DECLINED;
  } else {
    apr_table_t *tl;
    parp_t *parp = parp_new(r, PARP_FLAGS_NONE);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  PARP_LOG_PFX(000)"enabled (%s)", e);

    status = parp_read_params(parp);
    ap_set_module_config(r->request_config, &parp_module, parp);
    ap_add_input_filter("parp-forward-filter", parp, r, r->connection);
    if(status == APR_SUCCESS) {
      parp_get_params(parp, &tl);
      status = parp_run_hp_hook(r, tl);
    } else {
      parp_srv_config *sconf = (parp_srv_config*)ap_get_module_config(r->server->module_config,
                                                                      &parp_module);
      char *error = parp_get_error(parp);

      ap_log_rerror(APLOG_MARK, sconf->onerror == 200 ? APLOG_WARNING : APLOG_ERR, 0, r,
                    PARP_LOG_PFX(010)"parser error, rc=%d (%s)",
                    sconf->onerror == -1 ? 500 : sconf->onerror,
                    error == NULL ? "-" : error);
      if(sconf->onerror == 200) {
        return DECLINED;
      }
      if(sconf->onerror == -1) {
        status = HTTP_INTERNAL_SERVER_ERROR;
      } else {
        status = sconf->onerror;
      }
    }
  }
  return status;
}

static void *parp_srv_config_create(apr_pool_t *p, server_rec *s) {
  parp_srv_config *sconf = apr_pcalloc(p, sizeof(parp_srv_config));
  sconf->onerror = -1; /* -1 is handles same as 500 but is the default (used for merger) */
  return sconf;
}

static void *parp_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  parp_srv_config *b = (parp_srv_config *)basev;
  parp_srv_config *o = (parp_srv_config *)addv;
  if(o->onerror == -1) {
    return b;
  }
  return o;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
const char *parp_error_code_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  parp_srv_config *sconf = (parp_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                  &parp_module);
  sconf->onerror  = atoi(arg);
  if(sconf->onerror == 200) {
    return NULL;
  }
  if((sconf->onerror < 400) || (sconf->onerror > 599)) {
    return apr_psprintf(cmd->pool, "%s: error code must be a numeric value between 400 and 599", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const command_rec parp_config_cmds[] = {
  AP_INIT_TAKE1("PARP_ExitOnError", parp_error_code_cmd, NULL,
                RSRC_CONF,
                "PARP_ExitOnError <code>, defines the HTTP error code"
                " to return on parsing errors. Default is 500."
                " Specify 200 in order to ignore errors."),
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void parp_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", NULL };
  /* header parser is invoked after mod_setenvif */
  ap_hook_header_parser(parp_header_parser, pre, NULL, APR_HOOK_MIDDLE);
  ap_register_input_filter("parp-forward-filter", parp_forward_filter, NULL, AP_FTYPE_RESOURCE);
  APR_REGISTER_OPTIONAL_FN(parp_hp_table);
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
