/** main.c
    Main file for samdump2 2.x
    
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

    This program is released under the GPL with the additional exemption 
    that compiling, linking, and/or using OpenSSL is allowed.
    
    Copyright (C) 2008 Cedric Tissieres <http://www.objectif-securite.ch>
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "list.h"
#include "samdump2.h"
#include "hive.h"


void usage() {
  printf("samdump2 3.0.0 by Objectif Securite (http://www.objectif-securite.ch)\noriginal author: ncuomo@studenti.unina.it\n\n");
#ifdef WIN32
  printf("Usage: samdump2 [OPTION] -l (pwdump-like, only on Windows)\n");
#endif
  printf("Usage: samdump2 [OPTION]... SYSTEM_FILE SAM_FILE\n");
  printf("Retrieves syskey and extract hashes from Windows 2k/NT/XP/Vista SAM\n\n");
  printf("  -d\t\tenable debugging\n");
  printf("  -h\t\tdisplay this information\n");
#ifdef WIN32
  printf("  -l\t\textracts hashes from a live Windows, with low-level access to NTFS\n");
#endif
  printf("  -o file\twrite output to file\n");
}


int main( int argc, char **argv ) {

  unsigned char pkey[0x10];
  list_t *hash_list;
  list_nd_t *hash;
  char error[512];
  int debug=0, i=0, live=0;
  char *file=0;
  FILE *output;
  int c;
#ifdef WIN32
  unsigned char *buff_sam;
  int size = 0;
#endif

  while ((c = getopt(argc, argv, "hdlo:")) != -1)
    switch(c) {
    case 'd':
      debug = 1;
      break;
    case 'o':
      file = strdup(optarg);
      break;
    case 'h':
      usage();
      return -1;
      break;
#ifdef WIN32
    case 'l':
      live = 1;
      break;
#endif
    default:
      usage();
      return -1;
      break;
    }

  if (!live && argc-optind != 2) {
    usage();
    return -1;
  }

  if (file) {
    output = fopen(file, "w");
    if (output == 0) {
      printf("Cannot open file %s for writing.\n", file);
      exit(1);
    }
  }

  hash_list = list_alloc();

  if (!live) {
    if (bkhive((unsigned char *)argv[argc-2], pkey, error, debug) == -1) {
      printf("%s", error);
      exit(-1);
    }
    
    if (samdump2((unsigned char *)argv[argc-1], hash_list, pkey, error, debug, live, 0) == -1) {
      printf("%s", error);
      exit(-1);
    }
  } else {
#ifdef WIN32
    if (get_live_syskey(pkey, error, debug) == -1) {
      printf("%s", error);
      exit(-1);
    }
    
    if (get_sam(&buff_sam, &size, error, debug) == -1) {
      printf("%s", error);
      exit(-1);
    }

    if (samdump2(buff_sam, hash_list, pkey, error, debug, live, size) == -1) {
      printf("%s", error);
      exit(-1);
    }
#endif
  }

  hash = (list_nd_t *) hash_list->head;

  for (i=0; i<hash_list->size; i++) {
    if (file)
      fprintf(output, "%s\n", (char *)hash->data);
    else
      printf("%s\n", (char *)hash->data);
    hash = hash->prev;
  }
  
  if (file)
    fclose(output);

#ifdef WIN32
  free(buff_sam);
#endif

  return 0;
}
