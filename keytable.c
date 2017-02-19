/* keytable.c - This program allows checking/replacing keys at IR

   Copyright (C) 2006-2010 Mauro Carvalho Chehab

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/input.h>
#include <argp.h>

#include "parse.h"

#define _(string) string
#define N_(string) string

struct input_keymap_entry_v2 {
#define KEYMAP_BY_INDEX	(1 << 0)
  u_int8_t  flags;
  u_int8_t  len;
  u_int16_t index;
  u_int32_t keycode;
  u_int8_t  scancode[32];
};

#ifndef EVIOCGKEYCODE_V2
#define EVIOCGKEYCODE_V2	_IOR('E', 0x04, struct input_keymap_entry_v2)
#define EVIOCSKEYCODE_V2	_IOW('E', 0x04, struct input_keymap_entry_v2)
#endif

struct keytable_entry {
  u_int32_t scancode;
  u_int32_t keycode;
  struct keytable_entry *next;
};

struct keytable_entry *keytable = NULL;

static int parse_code(char *string)
{
  struct parse_event *p;

  for (p = key_events; p->name != NULL; p++) {
    if (!strcasecmp(p->name, string))
      return p->value;
  }
  return -1;
}

static const char doc[] = N_(
                            "\nAllows get/set keycode/scancode tables\n"
                            "\nOn the options below, the arguments are:\n"
                            "  DEV      - the /dev/input/event* device to control\n"
                            "  TABLE    - a file with a set of scancode=keycode value pairs\n"
                            "  SCANKEY  - a set of scancode1=keycode1,scancode2=keycode2.. value pairs\n"
                            "\nOptions can be combined together.");

static const struct argp_option options[] = {
  {"verbose",	'v',	0,		0,	N_("enables debug messages"), 0},
  {"clear",	'c',	0,		0,	N_("clears the old table"), 0},
  {"test",	't',	0,		0,	N_("test if device is generating events"), 0},
  {"device",	'd',	N_("DEV"),	0,	N_("input device to control"), 0},
  {"read",	'r',	0,		0,	N_("reads the current scancode/keycode table"), 0},
  {"write",	'w',	N_("TABLE"),	0,	N_("write (adds) the scancodes to the device scancode/keycode table from an specified file"), 0},
  {"set-key",	'k',	N_("SCANKEY"),	0,	N_("Change scan/key pairs"), 0},
  {"help",	'?',	0,		0,	N_("Give this help list"), -1},
  {"usage",	-3,	0,		0,	N_("Give a short usage message")},
  {"version",	'V',	0,		0,	N_("Print program version"), -1},
  { 0, 0, 0, 0, 0, 0 }
};

static const char args_doc[] = N_("--device [/dev/input/event* device]\n");
static char *devicename = NULL;
static int readtable = 0;
static int clear = 0;
static int debug = 0;
static int test = 0;
static int input_protocol_version = 0;

static error_t parse_keyfile(char *fname, char **table)
{
  FILE *fin;
  int value, line = 0;
  char *scancode, *keycode, s[2048];
  struct keytable_entry *ke;

  *table = NULL;

  if (debug)
    fprintf(stderr, _("Parsing %s keycode file\n"), fname);

  fin = fopen(fname, "r");
  if (!fin) {
    return errno;
  }

  while (fgets(s, sizeof(s), fin)) {
    char *p = s;

    line++;
    while (*p == ' ' || *p == '\t')
      p++;
    if (line==1 && p[0] == '#') {
      p++;
      p = strtok(p, "\n\t =:");
      do {
        if (!p)
          goto err_einval;
        if (!strcmp(p, "table")) {
          p = strtok(NULL,"\n, ");
          if (!p)
            goto err_einval;
          *table = malloc(strlen(p) + 1);
          strcpy(*table, p);
        } else {
          goto err_einval;
        }
        p = strtok(NULL, "\n\t =:");
      } while (p);
      continue;
    }

    if (*p == '\n' || *p == '#')
      continue;

    scancode = strtok(p, "\n\t =:");
    if (!scancode)
      goto err_einval;
    if (!strcasecmp(scancode, "scancode")) {
      scancode = strtok(NULL, "\n\t =:");
      if (!scancode)
        goto err_einval;
    }

    keycode = strtok(NULL, "\n\t =:(");
    if (!keycode)
      goto err_einval;

    if (debug)
      fprintf(stderr, _("parsing %s=%s:"), scancode, keycode);
    value = parse_code(keycode);
    if (debug)
      fprintf(stderr, _("\tvalue=%d\n"), value);

    if (value == -1) {
      value = strtol(keycode, NULL, 0);
      if (errno)
        perror(_("value"));
    }

    ke = calloc(1, sizeof(*ke));
    if (!ke) {
      perror("parse_keyfile");
      return ENOMEM;
    }

    ke->scancode	= strtoul(scancode, NULL, 0);
    ke->keycode	= value;
    ke->next	= keytable;
    keytable	= ke;
  }
  fclose(fin);

  return 0;

err_einval:
  fprintf(stderr, _("Invalid parameter on line %d of %s\n"),
          line, fname);
  return EINVAL;

}

static error_t parse_opt(int k, char *arg, struct argp_state *state)
{
  char *p;
  long key;
  int rc;

  switch (k) {
  case 'v':
    debug++;
    break;
  case 't':
    test++;
    break;
  case 'c':
    clear++;
    break;
  case 'd':
    devicename = arg;
    break;
  case 'r':
    readtable++;
    break;
  case 'w': {
    char *name = NULL;

    rc = parse_keyfile(arg, &name);
    if (rc)
      goto err_inval;
    if (name)
      fprintf(stderr, _("Read %s table\n"), name);
    break;
  }
  case 'k':
    p = strtok(arg, ":=");
    do {
      struct keytable_entry *ke;

      if (!p)
        goto err_inval;

      ke = calloc(1, sizeof(*ke));
      if (!ke) {
        perror(_("No memory!\n"));
        return ENOMEM;
      }

      ke->scancode = strtoul(p, NULL, 0);
      if (errno) {
        free(ke);
        goto err_inval;
      }

      p = strtok(NULL, ",;");
      if (!p) {
        free(ke);
        goto err_inval;
      }

      key = parse_code(p);
      if (key == -1) {
        key = strtol(p, NULL, 0);
        if (errno) {
          free(ke);
          goto err_inval;
        }
      }

      ke->keycode = key;

      if (debug)
        fprintf(stderr, _("scancode 0x%04x=%u\n"),
                ke->scancode, ke->keycode);

      ke->next = keytable;
      keytable = ke;

      p = strtok(NULL, ":=");
    } while (p);
    break;
  case '?':
    argp_state_help(state, state->out_stream,
                    ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG
                    | ARGP_HELP_DOC);
    exit(0);
  case -3:
    argp_state_help(state, state->out_stream, ARGP_HELP_USAGE);
    exit(0);
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;

err_inval:
  fprintf(stderr, _("Invalid parameter(s)\n"));
  return ARGP_ERR_UNKNOWN;

}

static struct argp argp = {
  .options = options,
  .parser = parse_opt,
  .args_doc = args_doc,
  .doc = doc,
};

static void prtcode(int *codes)
{
  struct parse_event *p;

  for (p = key_events; p->name != NULL; p++) {
    if (p->value == (unsigned)codes[1]) {
      printf(_("scancode 0x%04x = %s (0x%02x)\n"), codes[0], p->name, codes[1]);
      return;
    }
  }

  if (isprint (codes[1]))
    printf(_("scancode 0x%04x = '%c' (0x%02x)\n"), codes[0], codes[1], codes[1]);
  else
    printf(_("scancode 0x%04x = 0x%02x\n"), codes[0], codes[1]);
}

static int get_input_protocol_version(int fd)
{
  if (ioctl(fd, EVIOCGVERSION, &input_protocol_version) < 0) {
    fprintf(stderr,
            _("Unable to query evdev protocol version: %s\n"),
            strerror(errno));
    return errno;
  }
  if (debug)
    fprintf(stderr, _("Input Protocol version: 0x%08x\n"),
            input_protocol_version);

  return 0;
}

static void clear_table(int fd)
{
  int i, j;
  u_int32_t codes[2];
  struct input_keymap_entry_v2 entry;

  /* Clears old table */
  if (input_protocol_version < 0x10001) {
    for (j = 0; j < 256; j++) {
      for (i = 0; i < 256; i++) {
        codes[0] = (j << 8) | i;
        codes[1] = KEY_RESERVED;
        ioctl(fd, EVIOCSKEYCODE, codes);
      }
    }
  } else {
    memset(&entry, '\0', sizeof(entry));
    i = 0;
    do {
      entry.flags = KEYMAP_BY_INDEX;
      entry.keycode = KEY_RESERVED;
      entry.index = 0;

      i++;
      if (debug)
        fprintf(stderr, _("Deleting entry %d\n"), i);
    } while (ioctl(fd, EVIOCSKEYCODE_V2, &entry) == 0);
  }
}

static int add_keys(int fd)
{
  int write_cnt = 0;
  struct keytable_entry *ke;
  unsigned codes[2];

  for (ke = keytable; ke; ke = ke->next) {
    write_cnt++;
    if (debug)
      fprintf(stderr, "\t%04x=%04x\n",
              ke->scancode, ke->keycode);

    codes[0] = ke->scancode;
    codes[1] = ke->keycode;

    if (ioctl(fd, EVIOCSKEYCODE, codes)) {
      fprintf(stderr,
              _("Setting scancode 0x%04x with 0x%04x via "),
              ke->scancode, ke->keycode);
      perror("EVIOCSKEYCODE");
    }
  }

  while (keytable) {
    ke = keytable;
    keytable = ke->next;
    free(ke);
  }

  return write_cnt;
}

static char *get_event_name(struct parse_event *event, u_int16_t code)
{
  struct parse_event *p;

  for (p = event; p->name != NULL; p++) {
    if (p->value == code)
      return p->name;
  }
  return "";
}

static void test_event(int fd)
{
  struct input_event ev[64];
  int rd, i;

  printf (_("Testing events. Please, press CTRL-C to abort.\n"));
  while (1) {
    rd = read(fd, ev, sizeof(ev));

    if (rd < (int) sizeof(struct input_event)) {
      perror(_("Error reading event"));
      return;
    }

    for (i = 0; i < rd / sizeof(struct input_event); i++) {
      printf(_("%ld.%06ld: event type %s(0x%02x)"),
             ev[i].time.tv_sec, ev[i].time.tv_usec,
             get_event_name(events_type, ev[i].type), ev[i].type);

      switch (ev[i].type) {
      case EV_SYN:
        printf(".\n");
        break;
      case EV_KEY:
        printf(_(" key_%s: %s(0x%04x)\n"),
               (ev[i].value == 0) ? _("up") : _("down"),
               get_event_name(key_events, ev[i].code),
               ev[i].code);
        break;
      case EV_REL:
        printf(_(": %s (0x%04x) value=%d\n"),
               get_event_name(rel_events, ev[i].code),
               ev[i].type,
               ev[i].value);
        break;
      case EV_ABS:
        printf(_(": %s (0x%04x) value=%d\n"),
               get_event_name(abs_events, ev[i].code),
               ev[i].type,
               ev[i].value);
        break;
      case EV_MSC:
        if (ev[i].code == MSC_SCAN)
          printf(_(": scancode = 0x%02x\n"), ev[i].value);
        else
          printf(_(": code = %s(0x%02x), value = %d\n"),
                 get_event_name(msc_events, ev[i].code),
                 ev[i].code, ev[i].value);
        break;
      case EV_REP:
        printf(_(": value = %d\n"), ev[i].value);
        break;
      case EV_SW:
      case EV_LED:
      case EV_SND:
      case EV_FF:
      case EV_PWR:
      case EV_FF_STATUS:
      default:
        printf(_(": code = 0x%02x, value = %d\n"),
               ev[i].code, ev[i].value);
        break;
      }
    }
  }
}

static void display_table_v1(int fd)
{
  unsigned int i, j;

  for (j = 0; j < 256; j++) {
    for (i = 0; i < 256; i++) {
      int codes[2];

      codes[0] = (j << 8) | i;
      if (ioctl(fd, EVIOCGKEYCODE, codes) == -1)
        perror("EVIOCGKEYCODE");
      else if (codes[1] != KEY_RESERVED)
        prtcode(codes);
    }
  }
}

static void display_table_v2(int fd)
{
  int i;
  struct input_keymap_entry_v2 entry;
  int codes[2];

  memset(&entry, '\0', sizeof(entry));
  i = 0;
  do {
    entry.flags = KEYMAP_BY_INDEX;
    entry.index = i;
    entry.len = sizeof(u_int32_t);

    if (ioctl(fd, EVIOCGKEYCODE_V2, &entry) == -1)
      break;

    /* FIXME: Extend it to support scancodes > 32 bits */
    memcpy(&codes[0], entry.scancode, sizeof(codes[0]));
    codes[1] = entry.keycode;

    prtcode(codes);
    i++;
  } while (1);
}

static void display_table(int fd)
{
  if (input_protocol_version < 0x10001)
    display_table_v1(fd);
  else
    display_table_v2(fd);
}

static void device_info(int fd, char *prepend)
{
  struct input_id id;
  char buf[32];
  int rc;

  rc = ioctl(fd, EVIOCGNAME(sizeof(buf)), buf);
  if (rc >= 0)
    fprintf(stderr,_("%sName: %.*s\n"),prepend, rc, buf);
  else
    perror ("EVIOCGNAME");

  rc = ioctl(fd, EVIOCGID, &id);
  if (rc >= 0)
    fprintf(stderr,
            _("%sbus: %d, vendor/product: %04x:%04x, version: 0x%04x\n"),
            prepend, id.bustype, id.vendor, id.product, id.version);
  else
    perror ("EVIOCGID");
}

int main(int argc, char *argv[])
{
  int write_cnt;
  int fd;

  argp_parse(&argp, argc, argv, ARGP_NO_HELP | ARGP_NO_EXIT, 0, 0);

  if (!clear && !readtable && !keytable && !test) {
    if (devicename) {
      fd = open(devicename, O_RDONLY);
      if (fd < 0) {
        perror(_("Can't open device"));
        return -1;
      }
      device_info(fd, "");
      close(fd);
      return 0;
    }
    return 0;
  }

  if (debug)
    fprintf(stderr, _("Opening %s\n"), devicename);
  fd = open(devicename, O_RDONLY);
  if (fd < 0) {
    perror(devicename);
    return -1;
  }
  if (get_input_protocol_version(fd))
    return -1;

  if (clear) {
    clear_table(fd);
    fprintf(stderr, _("Old keytable cleared\n"));
  }

  write_cnt = add_keys(fd);
  if (write_cnt)
    fprintf(stderr, _("Wrote %d keycode(s) to driver\n"), write_cnt);

  if (readtable)
    display_table(fd);

  if (test)
    test_event(fd);

  return 0;
}
