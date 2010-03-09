/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */
/*  ____  _____  ____ ____  
 * |H _ \(____ |/ ___)  _ \ 
 * |T|_| / ___ | |   | |_| |
 * |T __/\_____|_|   |  __/ 
 * |P|ParameterParser|_|    
 * http://parp.sourceforge.net
 *
 * Copyright (C) 2008-2010 Christian Liesch/Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id$";
static const char g_revision[] = "0.9";

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
 
/**
 * parp hook
 */
typedef struct {
  apr_pool_t *pool;
  request_rec *r;
  apr_bucket_brigade *bb;
  char *raw_data;                     /** raw data received from the client */
  apr_size_t raw_data_len;            /** total length of the raw data (excluding modifications) */
  int use_raw;                        /** indicates the input filter to read the raw data instead of the bb */
  apr_table_t *params;                /** readonly parameter table (query+body) */
  apr_array_header_t *rw_body_params; /** writable table of parp_body_entry_t entries (null if no body available
                                          of no module has registered) */
  apr_table_t *parsers;               /** body parser per content type */
  char *error; 
  int flags;
  int recursion;
  char *data;
  apr_size_t len;
} parp_t;

/**
 * server configuration
 */
typedef struct {
  int onerror;
  apr_table_t *parsers;
} parp_srv_config;

/**
 * block
 */
typedef struct {
  apr_size_t len;
  char *data;
} parp_block_t;

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_module;

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(parp, PARP, apr_status_t, hp_hook,
                                    (request_rec *r, apr_table_t *table),
                                    (r, table),
                                    OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(parp, PARP, apr_status_t, modify_body_hook,
                                    (request_rec *r, apr_array_header_t *array),
                                    (r, array),
                                    OK, DECLINED)

/************************************************************************
 * functions
 ***********************************************************************/

typedef apr_status_t (*parp_parser_f)(parp_t *, apr_table_t *, char *, 
                                      apr_size_t);

static parp_parser_f parp_get_parser(parp_t *self, const char *ct); 

/**
 * Verifies if we may expext any body request data.
 */
static int parp_has_body(parp_t *self) {
  request_rec *r = self->r;
  const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
  const char *lenp = apr_table_get(r->headers_in, "Content-Length");
  if(tenc) {
    if(strcasecmp(tenc, "chunked") == 0) {
      return 1;
    }
  }
  if(lenp) {
    char *endstr;
    apr_off_t remaining;
    if((apr_strtoff(&remaining, lenp, &endstr, 10) == APR_SUCCESS) &&
       (remaining > 0)) {
      return 1;
    }
  }
  return 0;
}

/**
 * apr_brigade_pflatten() to null terminated string
 */
apr_status_t parp_flatten(apr_bucket_brigade *bb, char **c, apr_size_t *len, apr_pool_t *pool) {
  apr_off_t actual;
  apr_size_t total;
  apr_status_t rv;

  apr_brigade_length(bb, 1, &actual);
  total = (apr_size_t)actual;
  *c = apr_palloc(pool, total + 1);
  rv = apr_brigade_flatten(bb, *c, &total);
  *len = total;
  if (rv != APR_SUCCESS) {
    return rv;
  }
  (*c)[total] = '\0';
  return APR_SUCCESS;
}

/**
 * Read payload of this request (null terminated)
 *
 * @param r IN request record
 * @param data OUT flatten payload
 * @param len OUT len of payload
 *
 * @return APR_SUCCESS, any apr status code on error
 */
static apr_status_t parp_get_payload(parp_t *self) {
  char *data;
  apr_size_t len;
  apr_status_t status;

  request_rec *r = self->r;
  
  if ((status = parp_read_payload(r, self->bb, &self->error)) 
      != APR_SUCCESS) {
    return status;
  }
  
  if ((status = parp_flatten(self->bb, &data, &len, r->pool)) 
      != APR_SUCCESS) {
    self->error = apr_pstrdup(r->pool, "Input filter: apr_brigade_pflatten failed");
  } else {
    self->raw_data = data;
    self->raw_data_len = len;
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
          if(self->rw_body_params) {
            /* don't modify the raw data since we still need them */
            val = apr_pstrndup(self->pool, val, len - 1);
          } else {
            val[len - 1] = 0;
          }
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
  parp_block_t *boundary;
  
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
      /* prepare data finalize string with 0 */
      data[i - match] = 0;

      /* got it, store it */
      if (data[start]) {
        boundary = apr_pcalloc(self->pool, sizeof(*boundary));
	boundary->len = (i - match) - start;
	boundary->data = &data[start];
	apr_table_addn(tl, tag, (char *) boundary);
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
static apr_status_t parp_get_headers(parp_t *self, parp_block_t *b,
                                     apr_table_t **headers) {
  char *last;
  char *header;
  char *key;
  char *val;
  char *data = b->data;

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
  
  b->len -= last - data;
  b->data = last;
  
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
    const char *here = rest;
    pair = ap_getword(self->pool, &rest, '&');
    /* get key/value */
    val = pair;
    key = ap_getword_nc(self->pool, &val, '=');
    if (key && (key[0] >= ' ')) {
      /* store it to a table */
      int val_len = strlen(val);
      if (val_len >= 2 && strcmp(&val[val_len - 2], "\r\n") == 0) {
        if(self->rw_body_params) {
          val[val_len - 2] = 0;
        }
      }
      else if (val_len >= 1 && val[val_len - 1] == '\n') {
        val[val_len - 1] = 0;
      }
      apr_table_addn(self->params, key, val);
      /* store rw ref */
      if(self->rw_body_params) {
        parp_body_entry_t *entry = apr_array_push(self->rw_body_params);
        entry->key = key;
        entry->value = val;
        entry->new_value = NULL;
        entry->value_addr = &here[strlen(key)+1];
      }
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
  const char *ctd;
  const char *ct;
  const char *key;
  parp_parser_f parser;
  parp_block_t *b;
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
    b = (parp_block_t *)e[i].val;
    if ((status = parp_get_headers(self, b, &hs))) {
      return status;
    }

    if ((ct = apr_table_get(hs, "Content-Type"))) {
      parser = parp_get_parser(self, ct);
      if ((status = parser(self, hs, b->data, b->len)) != APR_SUCCESS && 
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

    /* if no content type is set the b->data is the parameters value */
    if (!ct) {
      char *val = b->data;
      if ((key = apr_table_get(ctds, "name")) == NULL) {
	return APR_EINVAL;
      }
      val_len = b->len;
      /* there must be a \r\n or at least a \n */
      if (val_len >= 2 && strcmp(&val[val_len - 2], "\r\n") == 0) {
        if(self->rw_body_params) {
          /* don't modify the raw data since we still need them */
          val = apr_pstrndup(self->pool, val, val_len - 2);
        } else {
          val[val_len - 2] = 0;
        }
      }
      else if (val_len >= 1 && val[val_len - 1] == '\n') {
        if(self->rw_body_params) {
          /* don't modify the raw data since we still need them */
          val = apr_pstrndup(self->pool, val, val_len - 1);
        } else {
          val[val_len - 1] = 0;
        }
      }
      else {
	return APR_EINVAL;
      }
      apr_table_add(self->params, key, val);
      if(self->rw_body_params) {
        parp_body_entry_t *entry = apr_array_push(self->rw_body_params);
        entry->key = key;
        entry->value = val;
        entry->new_value = NULL;
        entry->value_addr = b->data;
      }
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
 * To get body data from a content type not parsed
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_SUCCESS
 */
static apr_status_t parp_get_body(parp_t *self, apr_table_t *headers, 
                                  char *data, apr_size_t len) {
  self->data = data;
  self->len = len;
  return APR_SUCCESS;
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
      parp_srv_config *sconf = ap_get_module_config(self->r->server->module_config,
                                                    &parp_module);
      if (sconf->parsers) {
	parser = (parp_parser_f)apr_table_get(sconf->parsers, type);
      }
      if (!parser) {
	parser = (parp_parser_f)apr_table_get(self->parsers, type);
      }
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
 * Read payload of this request
 *
 * @param r IN request record
 * @param out IN bucket brigade to fill
 * @param error OUT error text if status != APR_SUCCESS
 *
 * @return APR_SUCCESS, any apr status code on error
 */
AP_DECLARE(apr_status_t )parp_read_payload(request_rec *r, 
                                           apr_bucket_brigade *out, 
			      	           char **error) {
  apr_status_t status;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  const char *buf;
  apr_size_t len;
  apr_off_t off;
  const char *enc;
  const char *len_str;

  int seen_eos = 0;

  if ((status = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK) {
    *error = apr_pstrdup(r->pool, "ap_setup_client_block failed");
    return status;
  }

  bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

  do {
    status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
 
    if (status == APR_SUCCESS) {
      while (!APR_BRIGADE_EMPTY(bb)) {
        b = APR_BRIGADE_FIRST(bb);
	APR_BUCKET_REMOVE(b);

	if (APR_BUCKET_IS_EOS(b)) {
	  seen_eos = 1;
	  APR_BRIGADE_INSERT_TAIL(out, b);
	}
	else if (APR_BUCKET_IS_FLUSH(b)) {
	  APR_BRIGADE_INSERT_TAIL(out, b);
	}
	else {
	  status = apr_bucket_read(b, &buf, &len, APR_BLOCK_READ);
	  if (status != APR_SUCCESS) {   
	    *error = apr_pstrdup(r->pool, "Input filter: Failed reading input");
	    return status;
	  }
	  apr_brigade_write(out, NULL, NULL, buf, len);
	  apr_bucket_destroy(b);
	}
      }
      apr_brigade_cleanup(bb);
    }
    else {
      seen_eos = 1;
    }
  } while (!seen_eos);

  apr_brigade_length(out, 1, &off);
   
  /* correct content-length header if deflate filter runs before */
  enc = apr_table_get(r->headers_in, "Transfer-Encoding");
  if (!enc || strcasecmp(enc, "chunked") != 0) {
    len_str = apr_off_t_toa(r->pool, off);
    apr_table_set(r->headers_in, "Content-Length", len_str);
    r->remaining = off;
  }

  return status;
}

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
  self->rw_body_params = NULL;;
  self->parsers = apr_table_make(r->pool, 3);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "application/x-www-form-urlencoded"), 
                (char *)parp_urlencode);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "multipart/form-data"), 
               (char *)parp_multipart);
  apr_table_setn(self->parsers, apr_pstrdup(r->pool, "multipart/mixed"), 
               (char *)parp_multipart);
  self->flags = flags;
  self->raw_data = NULL;
  self->raw_data_len = 0;
  self->use_raw = 0;
  self->data = NULL;
  self->len = 0;
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
  parp_parser_f parser;
  request_rec *r = self->r;
  int modify = 1;
  apr_array_header_t *hs = apr_optional_hook_get("modify_body_hook");
  if((hs == NULL) || (hs->nelts == 0)) {
    /* no module has registered */
    modify = 0;
  }
  if (r->args) {
    if ((status = parp_urlencode(self, r->headers_in, r->args, strlen(r->args))) 
        != APR_SUCCESS) {
      return status;
    }
  }
  if(parp_has_body(self)) {
    if(modify) {
      self->rw_body_params = apr_array_make(r->pool, 50, sizeof(parp_body_entry_t));
    }
    if ((status = parp_get_payload(self)) != APR_SUCCESS) {
      return status;
    }
    parser = parp_get_parser(self, apr_table_get(r->headers_in, "Content-Type"));  
    if ((status = parser(self, r->headers_in, self->raw_data, self->raw_data_len)) != APR_SUCCESS) {
      /* only set data to self pointer if untouched by parser, 
       * because parser could modify body data */
      if (status == APR_ENOTIMPL) {
      }
      return status;
    }
  }
  return APR_SUCCESS;
}

/**
 * Returns the pointer to the next modified element.
 * TODO: caching (don't iterate through all elements for every call)
 */
static parp_body_entry_t *parp_get_modified(parp_t *self) {
  int i;
  parp_body_entry_t *entries = (parp_body_entry_t *)self->rw_body_params->elts;
  for(i = 0; i < self->rw_body_params->nelts; ++i) {
    parp_body_entry_t *b = &entries[i];
    if(b->new_value) {
      if(b->value_addr > self->raw_data) {
        return b;
      }
    }
  }
  /* no element to insert */
  return NULL;
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

  if(self == NULL || (f->r && f->r->status != 200)) {
    /* nothing to do ... */
    return ap_get_brigade(f->next, bb, mode, block, nbytes);
  }
  
  if(self->use_raw) {
    /* forward data from the raw buffer and apply modifications */
    apr_off_t bytes = nbytes <= self->raw_data_len ? nbytes : self->raw_data_len;
    parp_body_entry_t *element = parp_get_modified(self);
    if(element && ((element->value_addr - self->raw_data) < bytes)) {
      /* element in range! */
      bytes = element->value_addr - self->raw_data;
    } else {
      element = NULL;
    }
    rv = apr_brigade_write(bb, NULL, NULL, self->raw_data, bytes); // TODO: apr_brigade_write() makes a copy
    self->raw_data = self->raw_data + bytes;
    self->raw_data_len -= bytes;
    if(element) {
      int slen = strlen(element->new_value);
      int olen = strlen(element->value);
      /* TODO: handle the case where size exeedes nbytes */
      rv = apr_brigade_write(bb, NULL, NULL, element->new_value, slen);
      self->raw_data = self->raw_data + olen;
      self->raw_data_len -= olen;
    }
    if(self->raw_data_len == 0) {
      /* our work is done so remove this filter */
      ap_remove_input_filter(f);
    }
  } else {
    /* transparent forwarding */
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

/**
 * Optional function which may be used by Apache modules
 * to access the body data. Only get data if not allready
 * parsed (and modified) and parser was active.
 *
 * @param r IN request record
 * @param len OUT body data len
 *
 * @return body data or NULL
 */
AP_DECLARE(const char *)parp_body_data(request_rec *r, apr_size_t *len) {
  parp_t *parp = ap_get_module_config(r->request_config, &parp_module);
  *len = 0;
  if(parp && parp->data) {
    *len = parp->len;
    return parp->data;
  }
  return NULL;
}

/**
 * Verifies if some values have been changed and adjust content length header. Also
 * sets the "use_raw" flag to signalize the input filter to forward the modifed data.
 */
static void parp_update_content_length(request_rec *r, parp_t *self, apr_off_t *contentlen) {
  apr_off_t len = *contentlen;
  int i;
  parp_body_entry_t *entries = (parp_body_entry_t *)self->rw_body_params->elts;
  for(i = 0; i < self->rw_body_params->nelts; ++i) {
    parp_body_entry_t *b = &entries[i];
    if(b->new_value) {
      len = len + strlen(b->new_value) - strlen(b->value);
      self->use_raw = 1;
    }
  }
  if(apr_table_get(r->headers_in, "Content-Length")) {
    apr_table_set(r->headers_in, "Content-Length", apr_psprintf(r->pool, "%"APR_OFF_T_FMT, len));
  }
  *contentlen = len;
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
        apr_off_t contentlen;
        parp_get_params(parp, &tl);
        apr_brigade_length(parp->bb, 1, &contentlen);
        status = parp_run_hp_hook(r, tl);
        if(parp->rw_body_params) {
          parp_run_modify_body_hook(r, parp->rw_body_params);
          parp_update_content_length(r, parp, &contentlen);
        }
        apr_table_set(r->subprocess_env,
                      "PARPContentLength",
                      apr_psprintf(r->pool, "%"APR_OFF_T_FMT, contentlen));
      } else {
        parp_srv_config *sconf = ap_get_module_config(r->server->module_config,
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
    o->onerror = b->onerror;
  }
  if(o->parsers == NULL) {
    o->parsers = b->parsers;
  }
  return o;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
const char *parp_error_code_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  parp_srv_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                &parp_module);
  sconf->onerror  = atoi(arg);
  if(sconf->onerror == 200) {
    return NULL;
  }
  if((sconf->onerror < 400) || (sconf->onerror > 599)) {
    return apr_psprintf(cmd->pool, "%s: error code must be a numeric value between 400 and 599"
                        " (or set 200 to ignore errors)",
                        cmd->directive->directive);
  }
  return NULL;
}

const char *parp_body_data_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  parp_srv_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                &parp_module);
  if (!sconf->parsers) {
    sconf->parsers = apr_table_make(cmd->pool, 5);
  }
  apr_table_setn(sconf->parsers, apr_pstrdup(cmd->pool, arg), 
                (char *)parp_get_body);
  return NULL;
}
  
static const command_rec parp_config_cmds[] = {
  AP_INIT_TAKE1("PARP_ExitOnError", parp_error_code_cmd, NULL,
                RSRC_CONF,
                "PARP_ExitOnError <code>, defines the HTTP error code"
                " to return on parsing errors. Default is 500."
                " Specify 200 in order to ignore errors."),
  AP_INIT_ITERATE("PARP_BodyData", parp_body_data_cmd, NULL,
                  RSRC_CONF,
                  "PARP_BodyData <content-type>, defines content"
		  " types where only the body data are read. Default is"
		  " no content type."),
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
  APR_REGISTER_OPTIONAL_FN(parp_body_data);
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
