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

/* Copyright (C) 2008 Christian Liesch / Pascal Buchbinder */

/*  ____  _____  ____ ____  
 * |H _ \(____ |/ ___)  _ \ 
 * |T|_| / ___ | |   | |_| |
 * |T __/\_____|_|   |  __/ 
 * |P|ParameterParser|_|    
 * http://parp.sourceforge.net
 */

#ifndef __MOD_PARP_H__
#define __MOD_PARP_H__

/**************************************************************************
 * Hooks 
 **************************************************************************/
#if !defined(WIN32)
#define PARP_DECLARE(type)            type
#define PARP_DECLARE_NONSTD(type)     type
#define PARP_DECLARE_DATA
#elif defined(PARP_DECLARE_STATIC)
#define PARP_DECLARE(type)            type __stdcall
#define PARP_DECLARE_NONSTD(type)     type
#define PARP_DECLARE_DATA
#elif defined(PARP_DECLARE_EXPORT)
#define PARP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define PARP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define PARP_DECLARE_DATA             __declspec(dllexport)
#else
#define PARP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define PARP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define PARP_DECLARE_DATA             __declspec(dllimport)
#endif

#define PARP_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(parp,name,fn,pre,succ,order)

APR_DECLARE_EXTERNAL_HOOK(parp, PARP, apr_status_t, hp_hook,
                          (request_rec *r, apr_table_t *table))


#endif /* __MOD_PARP_H__ */
