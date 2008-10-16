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

/**
 * @file
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
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>

/* self */
#include "param_parser.h" 
/**************************************************************************
 * Private 
 **************************************************************************/
struct parp_s {
  apr_pool_t *pool;
  request_rec *r;
  apr_bucket_brigade *bb;
  apr_table_t *params;
  apr_hash_t *parsers;
  char *error; 
  int flags;
  int recursion;
};

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
  apr_status_t status;
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
  apr_size_t i;
  apr_size_t start;
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
  apr_status_t status;
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
  apr_table_entry_t *elem;
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
      parser = apr_hash_get(self->parsers, type, APR_HASH_KEY_STRING);
    }
  }
  if (parser) {
    return parser;
  }
  else {
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
  self->parsers = apr_hash_make(r->pool);
  apr_hash_set(self->parsers, "application/x-www-form-urlencoded", 
               APR_HASH_KEY_STRING, parp_urlencode);
  apr_hash_set(self->parsers, "multipart/form-data", 
               APR_HASH_KEY_STRING, parp_multipart);
  apr_hash_set(self->parsers, "multipart/mixed", 
               APR_HASH_KEY_STRING, parp_multipart);
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
AP_DECLARE(const char *) parp_get_error(parp_t *self) {
  if (self && self->error) {
    return apr_pstrdup(self->pool, self->error);
  }
  else {
    return NULL;
  }
}

