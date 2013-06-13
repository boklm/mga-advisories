VERSION=0.5

PROJECTNAME=mga-advisories
BINFILES=mgaadv
CFGFILES=mga-advisories.conf
TMPLFILES=tmpl/*.html tmpl/*.txt tmpl/*.adv tmpl/*.rss

sysconfdir=/etc
bindir=/usr/bin
sharedir=/usr/share
projectdir=$(sharedir)/$(PROJECTNAME)
tmpldir=$(projectdir)/tmpl
perldir=/usr/lib/perl5/site_perl

all:

install:
	install -d $(DESTDIR)$(projectdir) $(DESTDIR)$(tmpldir) \
	    $(DESTDIR)$(bindir) $(DESTDIR)$(sysconfdir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -m 644 $(CFGFILES) $(DESTDIR)$(sysconfdir)
	install -m 644 $(TMPLFILES) $(DESTDIR)$(tmpldir)
	install -m 644 config_default $(DESTDIR)$(projectdir)/config
	install -d $(DESTDIR)$(perldir)/MGA
	install -m 644 lib/MGA/Advisories.pm $(DESTDIR)$(perldir)/MGA

tar:
	git archive --format=tar --prefix $(PROJECTNAME)-$(VERSION)/ HEAD | \
	    xz > $(PROJECTNAME)-$(VERSION).tar.xz
