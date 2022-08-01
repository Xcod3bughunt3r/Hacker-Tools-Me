# Copyright (C) 2006, Adam Cécile (Le_Vert) <gandalf@le-vert.net>
#	    (C) 2008, Cedric Tissieres <http://www.objectif-securite.ch>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-13, USA


# General variables
PACKAGE   = samdump2
VERSION   = 3.0.0
distdir   = $(PACKAGE)-$(VERSION)
DISTFILES = AUTHORS ChangeLog hive.c LICENSE list.h Makefile\
	samdump2.1 samdump2.h bkhive.c COPYING hive.h list.c\
	main.c README samdump2.c dumpsam.c ntdll.h
DESTDIR   = 
PREFIX    = /usr/local/
BINDIR    = $(PREFIX)/bin
MANDIR    = $(PREFIX)/share/man/man1
INSTALL   = $(shell which install)
CC	  = $(shell which gcc)
CFLAGS    = -Wall 
LIBS      = -lssl

# Default target
all: build

build: samdump2

samdump2: hive.o list.o bkhive.o samdump2.o main.o dumpsam.o
	@echo "Building binary..."
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	@echo ""

# Clean target
clean:
	@echo "Cleaning sources..."
	rm -f *.o samdump2 *~
	@echo ""

# Install target
install: build infos
	@echo "Creating directories..."
	$(INSTALL) -d -m 755 -o root -g root $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 -o root -g root $(DESTDIR)$(MANDIR)
	@echo "Copying binary..."
	$(INSTALL) samdump2 -m 755 -o root -g root $(DESTDIR)$(BINDIR)
	@echo "Installing man page..."
	$(INSTALL) samdump2.1 -m 644 -o root -g root $(DESTDIR)$(MANDIR)
	@echo ""

# Uninstall target
uninstall: infos
	@echo "Deleting binary and manpages..."
	rm -f $(DESTDIR)$(BINDIR)/samdump2
	rm -f $(DESTDIR)$(MANDIR)/samdump2.1
	@echo ""

dist: clean
	rm -rf $(distdir)
	mkdir $(distdir)
	cp $(DISTFILES) $(distdir)
	tar cfj $(distdir).tar.bz2 $(distdir)
	rm -rf $(distdir)

