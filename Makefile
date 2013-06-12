VERSION=0.4

PROJECTNAME=mga-advisories
BINFILES=mkadvisories
CFGFILES=mga-advisories.conf
TMPLFILES=tmpl/*.html tmpl/*.txt

sysconfdir=/etc
bindir=/usr/bin
sharedir=/usr/share
projectdir=$(sharedir)/$(PROJECTNAME)
tmpldir=$(projectdir)/tmpl

all:

install:
	install -d $(DESTDIR)$(projectdir) $(DESTDIR)$(tmpldir) \
	    $(DESTDIR)$(bindir) $(DESTDIR)$(sysconfdir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -m 644 $(CFGFILES) $(DESTDIR)$(sysconfdir)
	install -m 644 $(TMPLFILES) $(DESTDIR)$(tmpldir)
	install -m 644 config_default $(DESTDIR)$(projectdir)/config

tar:
	git archive --format=tar --prefix $(PROJECTNAME)-$(VERSION)/ HEAD | \
	    xz > $(PROJECTNAME)-$(VERSION).tar.xz
