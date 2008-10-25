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
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>

/* apr */
#include <apr_hooks.h>
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>

/* this */
#include "mod_parp.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define PARP_LOG_PFX(id)  "mod_parp("#id"): "

#define PARP_FLAGS_NONE 0
#define PARP_FLAGS_CONT_ON_ERR 1

/************************************************************************
 * structures
 ***********************************************************************/
struct parp_s {
  apr_pool_t *pool;
  request_rec *r;
  apr_bucket_brigade *bb;
  apr_table_t *params;
  apr_table_t *parsers;
  char *error; 
  int flags;
  int recursion;
};

typedef struct parp_s parp_t;

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

typedef apr_status_t (*parp_parser_f)(parp_t *, apr_table_t *, char *, 
                                      apr_size_t);

static parp_parser_f parp_get_parser(parp_t *self, const char *ct); 

/**
 * Read payload of this request
 *
 * @param r IN request record
 * @param data OUT flatten payload
 * @param len OUT len of payload
 *
 * @return APR_SUCCESS, any apr status code on error
 */
static apr_status_t parp_get_payload(parp_t *self, char **data, 
                                     apr_size_t *len) {
  apr_status_t status;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  const char *buf;
  apr_size_t buflen;

  request_rec *r = self->r;
  int seen_eos = 0;

  if ((status = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK) {
    self->error = apr_pstrdup(r->pool, "ap_setup_client_block failed");
    return status;
  }

  bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

  do {
    status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
 
    if (status == APR_SUCCESS) {
      for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);
	  b = APR_BUCKET_NEXT(b))
      {
	status = apr_bucket_read(b, &buf, &buflen, APR_BLOCK_READ);
	if (status != APR_SUCCESS) {   
	  self->error = apr_pstrdup(r->pool, "Input filter: Failed reading input");
          return status;
	}

	if (APR_BUCKET_IS_EOS(b)) {
	    seen_eos = 1;
	}
      }

      APR_BRIGADE_CONCAT(self->bb, bb);
      apr_brigade_cleanup(bb);
    }
    else {
      seen_eos = 1;
    }
  } while (!seen_eos);
  
  
  if ((status = apr_brigade_pflatten(self->bb, data, len, r->pool)) 
      != APR_SUCCESS) {
    self->error = apr_pstrdup(r->pool, "Input filter: apr_brigade_pflatten failed");
  }
  return status;
}

/**
 * read the content type contents
 *
 * @param self IN instance
 * @param headers IN headers
 * @param result OUT
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_read_header(parp_t *self, const char *header, 
                                     apr_table_t **result) {
  char *pair;
  char *key;
  char *val;
  char *last;
  apr_size_t len;

  apr_table_t *tl = apr_table_make(self->pool, 3);
  
  *result = tl;

  /* iterate over multipart key/value pairs */
  pair = apr_strtok(apr_pstrdup(self->pool, header), ";,", &last);
  if (!pair) {
    return APR_SUCCESS;
  }
  do {
    /* eat spaces */
    while (*pair == ' ') {
      ++pair;
    }
    /* get key/value */
    key = apr_strtok(pair, "=", &val);
    if (key) {
      /* strip " away */
      if (val && val[0] == '"') {
	++val;
	len = strlen(val);
	if (len > 0) {
	  val[len - 1] = 0;
	}
      }
      apr_table_addn(tl, key, val);
    }
  } while ((pair = apr_strtok(NULL, ";,", &last)));
  
  return APR_SUCCESS;
}

/**
 * read the all boundaries 
 *
 * @param self IN instance
 * @param data IN data to parse
 * @param len IN len of data
 * @param tag IN boundary tag
 * @param result OUT table of boundaries
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_read_boundaries(parp_t *self, char *data, 
                                         apr_size_t len, const char *tag,
					 apr_table_t **result) {
  apr_size_t i;
  apr_size_t start;
  apr_size_t match;
  apr_size_t tag_len;
  int incr;
  apr_table_t *tl;
  
  tl = apr_table_make(self->pool, 5);
  *result = tl;
  tag_len = strlen(tag);
  for (i = 0, match = 0, start = 0; i < len; i++) {
    /* test if match complete */
    if (match == tag_len) {
      if (strncmp(&data[i], "\r\n", 2) == 0) {
	incr = 2;
      }
      else if (strncmp(&data[i], "--\r\n", 4) == 0) {
	incr = 4;
      }
      else if (strcmp(&data[i], "--") == 0) {
	incr = 2;
      }
      else if (data[i] == '\n') {
	incr = 1;
      }
      else {
	match = 0;
	continue;
      }
      /* prepare data */
      data[i - match] = 0;

      /* got it, store it */
      if (data[start]) {
	apr_table_addn(tl, tag, &data[start]);
      }
      i += incr;
      start = i;
    }
    /* pattern matching */
    if (match < tag_len && data[i] == tag[match]) {
      ++match;
    }
    else {
      match = 0;
    }
  }

  return APR_SUCCESS;
}

/**
 * Get headers from data, all lines until first empty line will be 
 * split into header/value stored in the headers table.
 *
 * @param self IN instance
 * @param data IN data
 * @param len IN len of data
 * @param headers OUT found headers
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_get_headers(parp_t *self, char **rdata, apr_size_t len,
                                     apr_table_t **headers) {
  char *last;
  char *header;
  char *key;
  char *val;
  char *data = *rdata;

  apr_table_t *tl = apr_table_make(self->pool, 3);
  *headers = tl;
  
  header = apr_strtok(data, "\r\n", &last);
  while (header) {
    key = apr_strtok(header, ":", &val);
    if (val) {
      while (*val == ' ') ++val;
    }
    apr_table_addn(tl, key, val);

    if (*last == '\n') {
      ++last;
    }
    /* look if we have a empty line in front */
    if (strncmp(last, "\r\n", 2) == 0) {
      ++last;
      break;
    }
    header = apr_strtok(NULL, "\r\n", &last);
  }
  if (*last == '\n') {
    ++last;
  }
  
  *rdata = last;
  
  return APR_SUCCESS;
}

/**
 * Urlencode parser
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_urlencode(parp_t *self, apr_table_t *headers,
                                   const char *data, apr_size_t len) {
  char *key;
  char *val;
  char *pair;

  const char *rest = data;
  
  while (rest[0]) {
    pair = ap_getword(self->pool, &rest, '&');
    /* get key/value */
    val = pair;
    key = ap_getword_nc(self->pool, &val, '=');
    if (key) {
      /* store it to a table */
      apr_table_addn(self->params, key, val);
    }
  }
  
  return APR_SUCCESS;
}

/**
 * Multipart parser
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_multipart(parp_t *self, apr_table_t *headers, 
                                   char *data, apr_size_t len) {
  apr_status_t status;
  apr_size_t val_len;
  const char *boundary;
  apr_table_t *ctt;
  apr_table_t *bs;
  apr_table_t *ctds;
  apr_table_entry_t *e;
  int i;
  char *bdata;
  const char *ctd;
  const char *ct;
  const char *key;
  parp_parser_f parser;
  apr_table_t *hs = apr_table_make(self->pool, 3);
  
  if (self->recursion > 3) {
    self->error = apr_pstrdup(self->pool, "Too deep recursion of multiparts");
    return APR_EINVAL;
  }

  ++self->recursion;
  
  ct = apr_table_get(headers, "Content-Type");
  if (ct == NULL) {
    self->error = apr_pstrdup(self->pool, "No content type available");
    return APR_EINVAL;
  }

  if ((status = parp_read_header(self, ct, &ctt)) != APR_SUCCESS) {
    return status;
  }

  if (!(boundary = apr_table_get(ctt, "boundary"))) {
    return APR_EINVAL;
  }
  
  /* prefix boundary wiht a -- */
  boundary = apr_pstrcat(self->pool, "--", boundary, NULL);

  if ((status = parp_read_boundaries(self, data, len, boundary, &bs)) != APR_SUCCESS) {
    return status;
  }
  
  /* iterate over boundaries and store their param/value pairs */ 
  e = (apr_table_entry_t *) apr_table_elts(bs)->elts;
  for (i = 0; i < apr_table_elts(bs)->nelts; ++i) {
    /* read boundary headers */
    bdata = e[i].val;
    if ((status = parp_get_headers(self, &bdata, strlen(bdata), &hs))) {
      return status;
    }

    if ((ct = apr_table_get(hs, "Content-Type"))) {
      parser = parp_get_parser(self, ct);
      if ((status = parser(self, hs, bdata, strlen(bdata))) != APR_SUCCESS && 
	  status != APR_ENOTIMPL) {
	return status;
      }
    }
    
    if (!(ctd = apr_table_get(hs, "Content-Disposition"))) {
      return APR_EINVAL;
    }

    if ((status = parp_read_header(self, ctd, &ctds)) != APR_SUCCESS) {
      return status;
    }

    if (!ct) {
      if ((key = apr_table_get(ctds, "name")) == NULL) {
	return APR_EINVAL;
      }
      
      val_len = strlen(bdata);
      /* there must be a \r\n or at least a \n */
      if (val_len >= 2 && strcmp(&bdata[val_len - 2], "\r\n") == 0) {
	bdata[val_len - 2] = 0;
      }
      else if (val_len >= 1 && bdata[val_len - 1] == '\n') {
	bdata[val_len - 1] = 0;
      }
      else {
	return APR_EINVAL;
      }
      apr_table_add(self->params, key, bdata);
    }
    
  }
    
  /* now do all boundaries */
  return APR_SUCCESS;
}

/**
 * Not implemented parser used if there is no corresponding parser found
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_ENOTIMPL
 */
static apr_status_t parp_not_impl(parp_t *self, apr_table_t *headers, 
                                  char *data, apr_size_t len) {
  return APR_ENOTIMPL;
}

/**
 * Get content type parser
 *
 * @param self IN instance
 * @param ct IN content type (or NULL)
 *
 * @return content type parser
 */
static parp_parser_f parp_get_parser(parp_t *self, const char *ct) {
  const char *type;
  char *last;

  parp_parser_f parser = NULL;
  
  if (ct) {
    type = apr_strtok(apr_pstrdup(self->pool, ct), ";,", &last);
    if (type) {
      parser = (parp_parser_f)apr_table_get(self->parsers, type);
    }
  }
  if (parser) {
    return parser;
  }
  else {
    self->error = apr_psprintf(self->pool, "No parser available for this content type (%s)",
                               ct == NULL ? "-" : ct);
    return parp_not_impl;
  }
}

/**************************************************************************
 * Public
 **************************************************************************/
/**
 * Creates a new parameter parser.
 *
 * @param r IN request record
 *
 * @return new parameter parser instance
 */
AP_DECLARE(parp_t *) parp_new(request_rec *r, int flags) {
  parp_t *self = apr_pcalloc(r->pool, sizeof(parp_t));

  self->pool = r->pool;
  self->r = r;
  self->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
  self->params = apr_table_make(r->pool, 5);
  self->parsers = apr_table_make(r->pool, 3);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "application/x-www-form-urlencoded"), 
                (char *)parp_urlencode);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "multipart/form-data"), 
               (char *)parp_multipart);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "multipart/mixed"), 
               (char *)parp_multipart);
  self->flags = flags;

  return self;
}

/**
 * Get all parameter/value pairs in this request
 *
 * @param self IN instance
 * @param params OUT table of key/value pairs
 *
 * @return APR_SUCCESS or APR_EINVAL on parser errors
 *
 * @note: see parap_error(self) for detailed error message
 */
AP_DECLARE(apr_status_t) parp_read_params(parp_t *self) {
  apr_status_t status;
  char *data;
  apr_size_t len;
  parp_parser_f parser;

  request_rec *r = self->r;
  
  if (r->method_number == M_POST) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->headers_in, r->args, strlen(r->args))) 
	  != APR_SUCCESS) {
	return status;
      }
    }
    if ((status = parp_get_payload(self, &data, &len)) != APR_SUCCESS) {
      return status;
    }
    if (len > 2 && strncmp(&data[len-2], "\r\n", 2) == 0) {
      /* cut away the leading \r\n */
      data[len-2] = 0;
    }
    else if (len > 1 && data[len -1] == '\n'){
      /* cut away the leading \n */
      data[len-1] = 0;
    }
    else {
      data[len] = 0;
    }
    parser = parp_get_parser(self, apr_table_get(r->headers_in, 
	                                         "Content-Type"));  
    if ((status = parser(self, r->headers_in, data, len)) != APR_SUCCESS) {
      return status;
    }

  }
  else if (r->method_number == M_GET) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->headers_in, r->args, strlen(r->args))) 
	  != APR_SUCCESS) {
	return status;
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * Forward all data back to request.
 *
 * @param f IN filter
 * @param bb IN bucket brigade
 * @param mode IN 
 * @param block IN block mode
 * @param nbytes IN requested bytes
 *
 * @return any apr status
 */
AP_DECLARE (apr_status_t) parp_forward_filter(ap_filter_t * f, 
                                              apr_bucket_brigade * bb, 
					      ap_input_mode_t mode, 
					      apr_read_type_e block, 
					      apr_off_t nbytes) {
  apr_status_t rv;
  apr_bucket *e;
  apr_size_t len;
  const char *buf;

  apr_off_t read = 0;
  parp_t *self = f->ctx;

  if(self == NULL) {
    /* nothing to do ... */
    return ap_get_brigade(f->next, bb, mode, block, nbytes);
  }

  /* do never send a bigger brigade than request with "nbytes"! */
  while (read < nbytes && !APR_BRIGADE_EMPTY(self->bb)) {
    e = APR_BRIGADE_FIRST(self->bb);
    rv = apr_bucket_read(e, &buf, &len, block);

    if (rv != APR_SUCCESS) {
      return rv;
    }

    if (len + read > nbytes) {
      apr_bucket_split(e, nbytes - read);
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(bb, e);
      return APR_SUCCESS;
    }

    APR_BUCKET_REMOVE(e);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    read += len; 
  }
  
  if (APR_BRIGADE_EMPTY(self->bb)) {
    /* our work is done so remove this filter */
    ap_remove_input_filter(f);
  }

  return APR_SUCCESS;
}

/**
 * Get all parameter/value pairs in this request
 *
 * @param self IN instance
 * @param params OUT table of key/value pairs
 *
 * @return APR_SUCCESS
 */
AP_DECLARE(apr_status_t) parp_get_params(parp_t *self, apr_table_t **params) {
  *params = self->params;
  return APR_SUCCESS;
}

/**
 * Get error message on error
 *
 * @param self IN instance
 *
 * @return error message, empty message or NULL if instance not valid
 */
AP_DECLARE(char *) parp_get_error(parp_t *self) {
  if (self && self->error) {
    return apr_pstrdup(self->pool, self->error);
  }
  else {
    return NULL;
  }
}

/**
 * Optional function which may be used by Apache modules
 * to access the parameter table.
 *
 * @param r IN request record
 *
 * @return table with the request parameter or NULL if not available
 */
AP_DECLARE(apr_table_t *)parp_hp_table(request_rec *r) {
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
  if(ap_is_initial_req(r)) {
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
