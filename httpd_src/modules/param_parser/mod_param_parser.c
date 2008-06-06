/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */

/**
 * @file
 *
 */

/************************************************************************
 * Includes
 ***********************************************************************/
/* apache */
#include <httpd.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <util_filter.h>

/* apr */

/* param parser */
#include "param_parser.h"
  
/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/
  
module AP_MODULE_DECLARE_DATA param_parser_module;

/************************************************************************
 * Private 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/

/************************************************************************
 * Wellknown apache handlers
 ***********************************************************************/

/**
 * post config hook.
 *
 * @param pconf IN configuration pool
 * @param plog IN log pool
 * @param ptemp IN temp pool, will be deleted on return
 * @param s IN server record
 *
 * @return DECLINED
 */
static int pp_post_config(apr_pool_t * pconf, apr_pool_t * plog, 
                           apr_pool_t * ptemp, server_rec * s) {
  return DECLINED;
}

/**
 * access checker hook.
 *
 * @param r IN request record
 *
 * @return DECLINED 
 */
static int pp_access_checker(request_rec * r) {
  parp_t *parp;
  apr_table_t *tl;

  parp = parp_new(r);
  parp_get_params(parp, &tl);

  return DECLINED;
}

/************************************************************************
 * Wellknown apache directiv handlers 
 ***********************************************************************/
/**
 * create dir config
 *
 * @param p IN pool
 * @param dir IN dir/location name
 *
 * @return dir config
 */
static void *pp_dconf_create(apr_pool_t * p, char *dir) {
  return NULL;
}

/**
 * create server config
 *
 * @param p IN pool
 * @param s IN server record 
 *
 * @return server config
 */
static void *pp_sconf_create(apr_pool_t * p, server_rec *s) {
  return NULL;
}

/**
 * merge dir config
 *
 * @param p IN pool
 * @param basev IN void pointer to base dir config
 * @param addv IN void pointer to sub dir config
 *
 * @return merged dir config
 */
static void *pp_dconf_merge(apr_pool_t * p, void *basev, void *addv) {
  return NULL;
}

/**
 * merge server config
 *
 * @param p IN pool
 * @param basev IN void pointer to base server config
 * @param addv IN void pointer to sub server config
 *
 * @return merged dir config
 */
static void *pp_sconf_merge(apr_pool_t * p, void *basev, void *addv) {
  return NULL;
}

/**
 * command
 *
 * @param cmd IN command parameters
 * @param dcfg IN void pointer to dir config
 * @param arg IN argument
 *
 * @return NULL of error text
 */
static const char *pp_cmd(cmd_parms * cmd, void *dcfg, const char *arg) {
  return NULL;
}

static const command_rec pp_config_cmds[] = {
  AP_INIT_ITERATE("SKL_dummy1", pp_cmd, NULL,
                  ACCESS_CONF | RSRC_CONF,
                  "SKL_dummy1 <any>, param_parser dummy command one, default is 'this'"),
  AP_INIT_TAKE1("SKL_dummy2", pp_cmd, NULL,
                ACCESS_CONF | RSRC_CONF,
                "SKL_dummy1 <any>, param_parser dummy command two, default is 'that'"),
  { NULL }
};

/************************************************************************
 * Wellknown apache register 
 ***********************************************************************/
/**
 * register module hooks
 *
 * @param p IN pool
 */
static void pp_register_hooks(apr_pool_t * p) {
  /* register hooks */
  ap_hook_post_config(pp_post_config, NULL, NULL, APR_HOOK_LAST);
  ap_hook_access_checker(pp_access_checker, NULL, NULL, APR_HOOK_LAST);
  ap_register_input_filter("parap-forward-filter",
                           parp_forward_filter, NULL, AP_FTYPE_RESOURCE);
}

/************************************************************************
 * Wellknown apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA param_parser_module = {
  STANDARD20_MODULE_STUFF,
  pp_dconf_create,                         /**< dir config creater */
  pp_dconf_merge,                          /**< dir merger */
  pp_sconf_create,                         /**< server config */
  pp_sconf_merge,                          /**< server merger */
  pp_config_cmds,                          /**< command table */
  pp_register_hooks,                       /**< hook registery */
};
