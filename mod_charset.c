/*
 * ProFTPD - mod_charset
 * Copyright (c) 2012 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: utf8.c,v 1.16 2011/05/23 21:03:12 castaglia Exp $
 */

#include "conf.h"

#define MOD_CHARSET_VERSION	"mod_charset/0.0"

#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

#ifdef HAVE_ICONV_H
# include <iconv.h>
#endif

#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif

module charset_module;

static int charset_engine = FALSE;
static pool *charset_pool = NULL;

static const char *remote_charset = NULL;
static const char *local_charset = NULL;
static const char *trace_channel = "charset";

static int charset_decoder_free(void);
static int charset_decoder_init(const char *, const char *);

#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
static iconv_t decode_conv = (iconv_t) -1;

static int charset_convert(iconv_t conv, const char *inbuf, size_t *inbuflen,
    char *outbuf, size_t *outbuflen) {
# ifdef HAVE_ICONV

  /* Reset the state machine before each conversion. */
  (void) iconv(conv, NULL, NULL, NULL, NULL);

  while (*inbuflen > 0) {
    size_t nconv;

    pr_signals_handle();

    /* Solaris/FreeBSD's iconv(3) takes a const char ** for the input buffer,
     * whereas Linux/Mac OSX iconv(3) use char ** for the input buffer.
     */
#if defined(LINUX) || defined(DARWIN6) || defined(DARWIN7) || \
    defined(DARWIN8) || defined(DARWIN9) || defined(DARWIN10) || \
    defined(DARWIN11)
 
    nconv = iconv(conv, (char **) &inbuf, inbuflen, &outbuf, outbuflen);
#else
    nconv = iconv(conv, &inbuf, inbuflen, &outbuf, outbuflen);
#endif

    if (nconv == (size_t) -1) {

      /* Note: an errno of EILSEQ here can indicate badly encoded strings OR
       * (more likely) that the source character set used in the iconv_open(3)
       * call for this iconv_t descriptor does not accurately describe the
       * character encoding of the given string.  E.g. a filename may use
       * the ISO8859-1 character set, but iconv_open(3) was called using
       * US-ASCII.
       */

      return -1;
    }

    /* XXX We should let the loop condition work, rather than breaking out
     * of the loop here.
     */
    break;
  }

  return 0;

# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */

static int charset_decoder_free(void) {
# if defined(PR_USE_NLS) && defined(HAVE_ICONV)
  int res = 0;

  /* Close the iconv handles. */
  if (decode_conv != (iconv_t) -1) {
    res = iconv_close(decode_conv);
    if (res < 0) {
      pr_trace_msg(trace_channel, 1,
        "error closing decoding conversion handle from '%s' to '%s': %s",
          remote_charset, local_charset, strerror(errno));
      res = -1;
    }

    decode_conv = (iconv_t) -1;
  }

  return res;
# else
  errno = ENOSYS;
  return -1;
# endif
}

static int charset_decoder_init(const char *remote, const char *local) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV)
  remote_charset = remote;

  if (local == NULL) {
    local_charset = pr_encode_get_local_charset();

  } else {
    local_charset = local;
  }

  /* Get the iconv handles. */
  decode_conv = iconv_open(local_charset, remote_charset);
  if (decode_conv == (iconv_t) -1) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error opening conversion handle from '%s' "
      "to '%s': %s", remote_charset, local_charset, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
# else
  errno = ENOSYS;
  return -1;
#endif /* HAVE_ICONV */
}

static char *charset_decode_str(pool *p, const char *str) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
  size_t inlen, inbuflen, outlen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res = NULL;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (decode_conv == (iconv_t) -1) {
    pr_trace_msg(trace_channel, 1, "decoding conversion handle is invalid, "
      "unable to decode '%s' string", remote_charset);
    errno = EPERM;
    return NULL;
  }

  /* If the local charset matches the remote charset (i.e. local_charset is
   * "UTF-8"), then there's no point in converting; the charsets are the
   * same.  Indeed, on some libiconv implementations, attempting to
   * convert between the same charsets results in a tightly spinning CPU
   * (see Bug#3272).
   */
  if (strcasecmp(local_charset, remote_charset) == 0) {
    return (char *) str;
  }

  inlen = strlen(str) + 1;
  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, str, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (charset_convert(decode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error decoding string: %s",
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, outlen);
  memcpy(res, outbuf, outlen);

  return res;
#else
  errno = ENOSYS;
  return NULL;
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */
}

/* Configuration Handlers
 */

/* usage: CharsetEngine on|off */
MODRET set_charsetengine(cmd_rec *cmd) {
  config_rec *c;
  int engine = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: CharsetRequired remote|remote local */
MODRET set_charsetrequired(cmd_rec *cmd) {
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  if (cmd->argc == 2) {
    char *remote;

    remote = cmd->argv[1];

    /* Canonicalize various different ways of saying UTF8. */
    if (strncasecmp(remote, "utf8", 4) == 0) {
      remote = "UTF-8";
    }

    (void) add_config_param_str(cmd->argv[0], 1, remote);

  } else if (cmd->argc == 3) {
    char *remote, *local;

    remote = cmd->argv[1];
    local = cmd->argv[2];

    /* Canonicalize various different ways of saying UTF8. */
    if (strncasecmp(remote, "utf8", 4) == 0) {
      remote = "UTF-8";
    }

    if (strncasecmp(local, "utf8", 4) == 0) {
      local = "UTF-8";
    }

    (void) add_config_param_str(cmd->argv[0], 2, remote, local);

  } else {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  return PR_HANDLED(cmd);
}

/* Command Handlers
 */

MODRET charset_pre_cmd(cmd_rec *cmd) {
  char *res;

  if (charset_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  res = charset_decode_str(cmd->tmp_pool, cmd->arg);
  if (res == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG3, MOD_CHARSET_VERSION
      ": %s denied: unable to decode '%s': %s", cmd->argv[0], cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_501, "%s: %s", cmd->arg, strerror(xerrno));

    errno = xerrno;
    return PR_ERROR(cmd);

  } else {
    pr_trace_msg(trace_channel, 8, "decoded %s path '%s' to '%s'",
      cmd->argv[0], cmd->arg, res);
  }

  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

static void charset_exit_ev(const void *event_data, void *user_data) {
  (void) charset_decoder_free();
}

#if defined(PR_SHARED_MODULE)
static void charset_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_charset.c", (const char *) event_data) == 0) {
    destroy_pool(charset_pool);
    charset_pool = NULL;

    pr_event_unregister(&charset_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Module Initialization
 */

static int charset_init(void) {
  charset_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(charset_pool, MOD_CHARSET_VERSION);

  pr_event_register(&charset_module, "core.exit", charset_exit_ev, NULL);
#if defined(PR_SHARED_MODULE)
  pr_event_register(&charset_module, "core.module-unload",
    charset_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

static int charset_sess_init(void) {
  config_rec *c;
  int res;
  const char *remote, *local = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "CharsetEngine", FALSE);
  if (c != NULL) {
    charset_engine = *((int *) c->argv[0]);
  }

  if (charset_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "CharsetRequired", FALSE);
  if (c == NULL) {
    pr_log_debug(DEBUG3, MOD_CHARSET_VERSION
      ": CharsetRequired not configured, not performing any checks");
    charset_engine = FALSE;
    return 0;
  }

  if (c->argc == 1) {
    remote = c->argv[0];

  } else if (c->argc == 2) {
    remote = c->argv[0];
    local = c->argv[1];
  }

  (void) charset_decoder_free();

  res = charset_decoder_init(remote, local);
  if (res < 0) {
    pr_log_debug(DEBUG0, MOD_CHARSET_VERSION
      ": error initializing '%s' decoder: %s", remote, strerror(errno));
    return -1;
  }

  pr_trace_msg(trace_channel, 8,
    "requiring filenames convertible from '%s' to '%s'", remote_charset,
    local_charset);
  return 0;
}

/* Module API tables
 */

static conftable charset_conftab[] = {
  { "CharsetEngine",		set_charsetengine,	NULL },
  { "CharsetRequired",		set_charsetrequired,	NULL },
  { NULL }
};

static cmdtable charset_cmdtab[] = {
  { PRE_CMD,	C_APPE,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_DELE,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_MKD,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_XMKD,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_RNFR,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_RNTO,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_STOR,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_XMKD,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },

  { 0, NULL }
};

module charset_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "charset",

  /* Module configuration handler table */
  charset_conftab,

  /* Module command handler table */
  charset_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  charset_init,

  /* Session initialization function */
  charset_sess_init,

  /* Module version */
  MOD_CHARSET_VERSION
};

