package MGA::Advisories;

use warnings;
use strict;
use YAML qw(LoadFile DumpFile);
use Template;
use DateTime;
use Email::Sender::Simple qw(try_to_sendmail);
use Email::Simple;
use Email::Simple::Creator;
#use Data::Dump qw(dd);

my $config_file = '/usr/share/mga-advisories/config';
my $config = LoadFile($ENV{MGAADV_CONF} || $config_file);
my $home_config_file = $ENV{HOME} . '/.mga-advisories/mga-advisories.conf';
my $custom_config_file = -f $home_config_file ? $home_config_file 
        : '/etc/mga-advisories.conf';
my $custom_config = LoadFile($custom_config_file);
foreach my $k (keys %$custom_config) {
    $config->{$k} = $custom_config->{$k};
}

my %basename = (
    CVE => sub { $_[0] },
    ID  => sub { $_[0] },
    rel => sub { $_[0] },
    src => sub { 'src_' . $_[0] },
);

my %tools = (
    pkgname => sub { $_[0] =~ m/(.+)-[^-]+-[^-]+/; $1; },
);

my @report_logs;
sub report_log {
    push @report_logs, @_;
}

sub report_exit {
    report_log($_[0]);
    send_report_mail({ error => $_[0] });
    exit 1;
}

sub status_file {
    $config->{status_dir} . '/' . $_[0];
}

sub save_status {
    my ($advdb, $adv) = @_;
    my $statusfile = status_file($adv);
    DumpFile($statusfile, $advdb->{advisories}{$adv}{status});
}

sub get_advisories {
    my %advisories;
    foreach my $advfile (glob "$config->{advisories_dir}/*.adv") {
        my $adv = LoadFile($advfile);
        next unless $adv->{ID};
        report_exit("Duplicate advisory $adv->{ID}") if $advisories{$adv->{ID}};
        $advisories{$adv->{ID}} = $adv;
        my $statusfile = status_file($adv->{ID});
        $adv->{status} = -f $statusfile ? LoadFile($statusfile) : {};
    }
    return \%advisories;
}

sub publish_advisories {
    my ($advdb) = @_;
    foreach my $adv (keys %{$advdb->{advisories}}) {
        next if $advdb->{advisories}{$adv}{status}{published};
        $advdb->{advisories}{$adv}{status}{published} =
                $advdb->{advisories}{$adv}{pubtime} || time();
        save_status($advdb, $adv);
    }
}

sub sort_advisories {
    my ($advdb) = @_;
    foreach my $adv (keys %{$advdb->{advisories}}) {
        push @{$advdb->{by_type}{$advdb->{advisories}{$adv}{type}}}, $adv;
        foreach my $cve (@{$advdb->{advisories}{$adv}{CVE}}) {
            push @{$advdb->{by_cve}{$cve}}, $adv;
        }
        foreach my $rel (keys %{$advdb->{advisories}{$adv}{src}}) {
            push @{$advdb->{by_rel}{$rel}}, $adv;
            foreach my $media (keys %{$advdb->{advisories}{$adv}{src}{$rel}}) {
                push @{$advdb->{by_media}{$media}}, $adv;
                my %pkgs;
                foreach my $srpm (@{$advdb->{advisories}{$adv}{src}{$rel}{$media}}) {
                    my $pkgname = $tools{pkgname}->($srpm);
                    push @{$advdb->{by_src}{$pkgname}}, $adv
                        unless grep { $_ eq $adv } @{$advdb->{by_src}{$pkgname}};
                }
            }
        }
    }
}

sub process_template {
    my ($template, $src, $vars, $dest, $ext) = @_;
    foreach my $extension ($ext ? $ext : @{$config->{output_format}}) {
        next unless -f "$config->{tmpl_dir}/$src.$extension";
        $template->process("$src.$extension", $vars, ref $dest ? $dest : "$dest.$extension")
                || die $template->error, "\n";
    }
}

sub output_pages {
    my ($advdb) = @_;
    my $template = Template->new(
        INCLUDE_PATH => $config->{tmpl_dir},
        OUTPUT_PATH  => $config->{out_dir},
    );
    foreach my $adv (keys %{$advdb->{advisories}}) {
        my $vars = {
            config   => $config,
            advisory => $adv,
            advdb    => $advdb,
            basename => \%basename,
            tools    => \%tools,
        };
        process_template($template, 'advisory', $vars, $basename{ID}->($adv));
    }
    foreach my $by (['rel', 'by_rel'], ['CVE', 'by_cve'], ['src', 'by_src']) {
        foreach my $r (keys %{$advdb->{$by->[1]}}) {
            my $vars = {
                config   => $config,
                $by->[0] => $r,
                advdb    => $advdb,
                basename => \%basename,
                tools    => \%tools,
            };
            process_template($template, $by->[1], $vars, $basename{$by->[0]}->($r));
        }
    }
    my $vars = {
        config   => $config,
        advdb    => $advdb,
        basename => \%basename,
        tools    => \%tools,
    };
    process_template($template, 'index', $vars, 'index');
    process_template($template, 'advisories', $vars, 'advisories');
    process_template($template, 'CVE', $vars, 'CVE');
}

sub send_adv_mail {
    my ($advdb) = @_;
    return unless $config->{send_adv_mail} eq 'yes';
    my $template = Template->new(
        INCLUDE_PATH => $config->{tmpl_dir},
    );
    foreach my $adv (keys %{$advdb->{advisories}}) {
        next if $advdb->{advisories}{$adv}{status}{mail_sent};
        my $mailcontent;
        my $vars = {
            config   => $config,
            advisory => $adv,
            advdb    => $advdb,
            basename => \%basename,
            tools    => \%tools,
        };
        process_template($template, 'advisory', $vars, \$mailcontent, 'txt');
        my $email = Email::Simple->create(
            header => [
                To   => $config->{adv_mail_to},
                From => $config->{adv_mail_from},
                Subject => "$adv: " . $advdb->{advisories}{$adv}{subject},
            ],
            body   => $mailcontent
        );
        if (try_to_sendmail($email)) {
            report_log("Advisory mail for $adv sent");
            $advdb->{advisories}{$adv}{status}{mail_sent} = time();
            save_status($advdb, $adv);
        } else {
            report_log("Error sending advisory mail $adv");
        }
    }
}

sub send_report_mail {
    my ($advdb) = @_;
    return unless $config->{send_report_mail} eq 'yes';
    return unless @report_logs;
    my $template = Template->new(
        INCLUDE_PATH => $config->{tmpl_dir},
    );
    my $mailcontent;
    my $vars = {
        config      => $config,
        advdb       => $advdb,
        report_logs => \@report_logs,
    };
    process_template($template, 'report', $vars, \$mailcontent, 'txt');
    my $email = Email::Simple->create(
        header => [
            To   => $config->{report_mail_to},
            From => $config->{report_mail_from},
            Subject => $advdb->{error} ? 'Advisories Error' : 'Advisories Update',
        ],
        body   => $mailcontent
    );
    try_to_sendmail($email);
}

sub dumpdb {
    my ($advdb) = @_;
    DumpFile($config->{out_dir} . '/advisories.yaml', $advdb->{advisories});
}

sub newadv {
    my ($type, $bugnum) = @_;
    my $file = $config->{advisories_dir} . '/' . $bugnum . '.adv';
    if (-f $file) {
        print STDERR "File $file already exists\n";
        return undef;
    }
    my $template = Template->new(
        INCLUDE_PATH => $config->{tmpl_dir},
        OUTPUT_PATH  => $config->{advisories_dir},
    );
    my $vars = {
        type   => $type,
        bugnum => $bugnum,
    };
    process_template($template, 'newadvisory', $vars, $bugnum, 'adv');
    return $file;
}

sub listadv {
    my ($advdb) = @_;
    print map { "$_: $advdb->{advisories}{$_}{subject}\n" } 
        sort keys %{$advdb->{advisories}};
}

sub showadv {
    my ($advdb, $adv) = @_;
    if (!$advdb->{advisories}{$adv}) {
        print STDERR "Cannot find advisory $adv\n";
        return undef;
    }
    my $template = Template->new(
        INCLUDE_PATH => $config->{tmpl_dir},
    );
    my $vars = {
        config   => $config,
        advisory => $adv,
        advdb    => $advdb,
        basename => \%basename,
        tools    => \%tools,
    };
    my $advtxt;
    process_template($template, 'advisory', $vars, \$advtxt, 'txt');
    print $advtxt;
}

1;
