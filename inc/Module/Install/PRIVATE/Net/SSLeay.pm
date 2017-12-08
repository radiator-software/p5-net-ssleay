#line 1
package Module::Install::PRIVATE::Net::SSLeay;

use strict;
use Module::Install::Base;
use File::Basename ();
use File::Spec;
use Config;
use Symbol qw(gensym);

use vars qw{$VERSION @ISA};
BEGIN {
    $VERSION = 0.01;
    @ISA     = qw{Module::Install::Base};
}

# Define this to one if you want to link the openssl libraries statically into 
# the Net-SSLeay loadable object on Windows
my $win_link_statically = 0;

sub ssleay {
    my ($self) = @_;

    $self->requires_external_cc;

    my $prefix = $self->find_openssl_prefix;
    my $exec   = $self->find_openssl_exec($prefix);

    unless (-x $exec) {
        print <<EOM;
*** Could not find OpenSSL
    If it's already installed, please set the OPENSSL_PREFIX environment
    variable accordingly. If it isn't installed yet, get the latest version
    from http://www.openssl.org/.
EOM
        exit 0; # according http://wiki.cpantesters.org/wiki/CPANAuthorNotes this is best-practice when "missing library"
    }

    $self->check_openssl_version($prefix, $exec);
    my $opts = $self->ssleay_get_build_opts($prefix, $exec);

    $self->makemaker_args(
        CCCDLFLAGS => $opts->{cccdlflags},
        OPTIMIZE => $opts->{optimize},
        INC => join(' ', map {"-I$_"} @{$opts->{inc_paths}}),
        LIBS => join(' ', (map {"-L$_"} @{$opts->{lib_paths}}), (map {"-l$_"} @{$opts->{lib_links}})),
    );

    if ( $self->prompt(
            "Do you want to run external tests?\n".
            "These tests *will* *fail* if you do not have network connectivity.",
            'n',
    ) =~ /^y/i ) {
        $self->tests('t/*/*.t t/*/*/*.t');
    } else {
        $self->tests('t/local/*.t t/handle/local/*.t');
    }
}

sub ssleay_get_build_opts {
    my ($self, $prefix, $exec) = @_;

    my $opts = {
        lib_links  => [],
        cccdlflags => '',
    };
    for ("$prefix/include", "$prefix/inc32", '/usr/kerberos/include') {
      push @{$opts->{inc_paths}}, $_ if -f "$_/openssl/ssl.h";
    }
    for ($prefix, "$prefix/lib64", "$prefix/lib", "$prefix/out32dll") {
      push @{$opts->{lib_paths}}, $_ if -d $_;
    }

    my $rsaref  = $self->ssleay_is_rsaref;

    print <<EOM;
*** Be sure to use the same compiler and options to compile your OpenSSL, perl,
    and Net::SSLeay. Mixing and matching compilers is not supported.
EOM

    if ($^O eq 'MSWin32') {
        print "*** RSAREF build on Windows not supported out of box" if $rsaref;
        if ($win_link_statically) {
            # Link to static libs
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC/static" if -d "$prefix/lib/VC/static";
        }
        else {
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC" if -d "$prefix/lib/VC";
        }

        my $found = 0;
        my @pairs = ();
        # Library names depend on the compiler
        @pairs = (['eay32','ssl32'],['crypto.dll','ssl.dll'],['crypto','ssl']) if $Config{cc} =~ /gcc/;
        @pairs = (['libeay32','ssleay32'],['libeay32MD','ssleay32MD'],['libeay32MT','ssleay32MT']) if $Config{cc} =~ /cl/;
        for my $dir (@{$opts->{lib_paths}}) {
          for my $p (@pairs) {
            $found = 1 if ($Config{cc} =~ /gcc/ && -f "$dir/lib$p->[0].a" && -f "$dir/lib$p->[1].a");
            $found = 1 if ($Config{cc} =~ /cl/ && -f "$dir/$p->[0].lib" && -f "$dir/p->[1].lib");
            if ($found) {
              $opts->{lib_links} = [$p->[0], $p->[1], 'crypt32']; # Some systems need this system lib crypt32 too
              $opts->{lib_paths} = [$dir];
              last;
            }
          }
        }
        if (!$found) {
          #fallback to the old behaviour
          push @{ $opts->{lib_links} }, qw( libeay32MD ssleay32MD libeay32 ssleay32 libssl32 crypt32);
        }
    }
    elsif ($^O eq 'VMS') {
        if (-r 'sslroot:[000000]openssl.cnf') {      # openssl.org source install
          @{ $opts->{lib_paths} } = 'SSLLIB';
          @{ $opts->{lib_links} } = qw( ssl_libssl32.olb ssl_libcrypto32.olb );
        }
        elsif (-r 'ssl$root:[000000]openssl.cnf') {  # HP install
            @{ $opts->{lib_paths} } = 'SYS$SHARE';
            @{ $opts->{lib_links} } = qw( SSL$LIBSSL_SHR32 SSL$LIBCRYPTO_SHR32 );
        }
        @{ $opts->{lib_links} } = map { $_ =~ s/32\b//g } @{ $opts->{lib_links} } if $Config{use64bitall};
    }
    else {
        push @{ $opts->{lib_links} },
             ($rsaref
              ? qw( ssl crypto RSAglue rsaref z )
              : qw( ssl crypto z )
             );

        if (($Config{cc} =~ /aCC/i) && $^O eq 'hpux') {
            print "*** Enabling HPUX aCC options (+e)\n";
            $opts->{optimize} = '+e -O2 -g';
        }

        if ( (($Config{ccname} || $Config{cc}) eq 'gcc') && ($Config{cccdlflags} =~ /-fpic/) ) {
            print "*** Enabling gcc -fPIC optimization\n";
            $opts->{cccdlflags} .= '-fPIC';
        }
    }
    # From HMBRAND to handle multple version of OPENSSL installed
    if (my $lp = join " " => map { "-L$_" } @{$opts->{lib_paths} || []}) 
    {
	my $mma = $self->makemaker_args;
	($mma->{uc $_} = $Config{$_}) =~ s/-L/$lp -L/ for qw( lddlflags ldflags );
    }
    return $opts;
}

sub ssleay_is_rsaref {
    my ($self) = @_;

    return $ENV{OPENSSL_RSAREF};
}

my $other_try = 0;
my @nopath;
sub check_no_path {            # On OS/2 it would be typically on default paths
    my $p;
    if (not($other_try++) and $] >= 5.008001) {
       use ExtUtils::MM;
       my $mm = MM->new();
       my ($list) = $mm->ext("-lssl");
       return unless $list =~ /-lssl\b/;
        for $p (split /\Q$Config{path_sep}/, $ENV{PATH}) {
           @nopath = ("$p/openssl$Config{_exe}",       # exe name
                      '.')             # dummy lib path
               if -x "$p/openssl$Config{_exe}"
       }
    }
    @nopath;
}

sub find_openssl_prefix {
    my ($self, $dir) = @_;

    if (defined $ENV{OPENSSL_PREFIX}) {
        return $ENV{OPENSSL_PREFIX};
    }

    my @guesses = (
	'/home/linuxbrew/.linuxbrew/opt/openssl/bin/openssl' => '/home/linuxbrew/.linuxbrew/opt/openssl', # LinuxBrew openssl
	'/usr/local/opt/openssl/bin/openssl' => '/usr/local/opt/openssl', # OSX homebrew openssl
	'/usr/local/bin/openssl'         => '/usr/local', # OSX homebrew openssl
	'/opt/local/bin/openssl'         => '/opt/local', # Macports openssl
	'/usr/bin/openssl'               => '/usr',
	'/usr/sbin/openssl'              => '/usr',
	'/opt/ssl/bin/openssl'           => '/opt/ssl',
	'/opt/ssl/sbin/openssl'          => '/opt/ssl',
	'/usr/local/ssl/bin/openssl'     => '/usr/local/ssl',
	'/usr/local/openssl/bin/openssl' => '/usr/local/openssl',
	'/apps/openssl/std/bin/openssl'  => '/apps/openssl/std',
	'/usr/sfw/bin/openssl'           => '/usr/sfw', # Open Solaris
	'C:\OpenSSL\bin\openssl.exe'     => 'C:\OpenSSL',
	'C:\OpenSSL-Win32\bin\openssl.exe'        => 'C:\OpenSSL-Win32',
	$Config{prefix} . '\bin\openssl.exe'      => $Config{prefix},           # strawberry perl
	$Config{prefix} . '\..\c\bin\openssl.exe' => $Config{prefix} . '\..\c', # strawberry perl
	'/sslexe/openssl.exe'            => '/sslroot',  # VMS, openssl.org
	'/ssl$exe/openssl.exe'           => '/ssl$root', # VMS, HP install
    );

    while (my $k = shift @guesses
           and my $v = shift @guesses) {
        if ( -x $k ) {
            return $v;
        }
    }
    (undef, $dir) = $self->check_no_path
       and return $dir;

    return;
}

sub find_openssl_exec {
    my ($self, $prefix) = @_;

    my $exe_path;
    for my $subdir (qw( bin sbin out32dll ia64_exe alpha_exe )) {
        my $path = File::Spec->catfile($prefix, $subdir, "openssl$Config{_exe}");
        if ( -x $path ) {
            return $path;
        }
    }
    ($prefix) = $self->check_no_path
       and return $prefix;
    return;
}

sub check_openssl_version {
    my ($self, $prefix, $exec) = @_;
    my ($major, $minor, $letter);

    {
        my $pipe = gensym();
        open($pipe, qq{"$exec" version |})
            or die "Could not execute $exec";
        my $output = <$pipe>;
        chomp $output;
        close $pipe;

	if ( ($major, $minor, $letter) = $output =~ /^OpenSSL\s+(\d+\.\d+)\.(\d+)([a-z]?)/ ) {
	    print "*** Found OpenSSL-${major}.${minor}${letter} installed in $prefix\n";
	} elsif ( ($major, $minor) = $output =~ /^LibreSSL\s+(\d+\.\d+)\.(\d+)/ ) {
	    print "*** Found LibreSSL-${major}.${minor} installed in $prefix\n";
	} else {
            die <<EOM
*** OpenSSL version test failed
    (`$output' has been returned)
    Either you have bogus OpenSSL or a new version has changed the version
    number format. Please inform the authors!
EOM
        }
    }

    if ($major < 0.9 || ($major == 0.9 && $minor < 3)) {
        print <<EOM;
*** That's too old!
    Please upgrade OpenSSL to the latest version (http://www.openssl.org/)
EOM
        exit 0; # according http://wiki.cpantesters.org/wiki/CPANAuthorNotes this is best-practice when "missing library"
    }

    if ($major == 1.1 && $minor > 0) {
        print <<EOM;
*** That's newer than what this module was tested with
    You should consider checking if there is a newer release of this module
    available. Everything will probably work OK, though.
EOM
    }
}

sub fixpath {
    my ($self, $text) = @_;

    my $sep = File::Spec->catdir('');
    $text =~ s{\b/}{$sep}g;

    return $text;
}

1;
