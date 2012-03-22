#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Data::Dumper;
use IO::Socket::INET;
use Net::SSLeay qw/XN_FLAG_RFC2253 ASN1_STRFLGS_ESC_MSB/;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

# --- commandline options and global variables

my ($g_host, $g_pem, $g_dump, $g_showusage);

GetOptions(
  'help|?'  => \$g_showusage,
  'dump'    => \$g_dump,
  'host=s@' => \$g_host,
  'pem=s@'  => \$g_pem,
) or $g_showusage = 1;

# --- subroutines

sub show_usage {
  die <<EOL;

Usage: $0 <options>
  -help -?                  show this help
  -pem <file>               process X509 certificate from file (PEM format)
  -host <ip_or_dns>:<port>  process X509 certificate presented by SSL server
  -dump                     full dump of X509 certificate info

Example:
  $0 -pem file1.pem
  $0 -pem file1.pem -pem file2.pem
  $0 -host twitter.com:443 -dump

EOL
}

sub get_cert_details {
  my $x509 = shift;
  my $rv = {};
  my $flag_rfc22536_utf8 = (XN_FLAG_RFC2253) & (~ ASN1_STRFLGS_ESC_MSB);

  die 'ERROR: $x509 is NULL, gonna quit' unless $x509;

  warn "Info: dumping subject\n";
  my $subj_name = Net::SSLeay::X509_get_subject_name($x509);
  my $subj_count = Net::SSLeay::X509_NAME_entry_count($subj_name);
  $rv->{subject}->{count} = $subj_count;
  $rv->{subject}->{oneline} = Net::SSLeay::X509_NAME_oneline($subj_name);
  $rv->{subject}->{print_rfc2253} = Net::SSLeay::X509_NAME_print_ex($subj_name);
  $rv->{subject}->{print_rfc2253_utf8} = Net::SSLeay::X509_NAME_print_ex($subj_name, $flag_rfc22536_utf8);
  $rv->{subject}->{print_rfc2253_utf8_decoded} = Net::SSLeay::X509_NAME_print_ex($subj_name, $flag_rfc22536_utf8, 1);
  for my $i (0..$subj_count-1) {
    my $entry = Net::SSLeay::X509_NAME_get_entry($subj_name, $i);
    my $asn1_string = Net::SSLeay::X509_NAME_ENTRY_get_data($entry);
    my $asn1_object = Net::SSLeay::X509_NAME_ENTRY_get_object($entry);
    my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
    $rv->{subject}->{entries}->[$i] = {
          oid  => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
          data => Net::SSLeay::P_ASN1_STRING_get($asn1_string),
          data_utf8_decoded => Net::SSLeay::P_ASN1_STRING_get($asn1_string, 1),
          nid  => ($nid>0) ? $nid : undef,
          ln   => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
          sn   => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,
    };
  }

  warn "Info: dumping issuer\n";
  my $issuer_name = Net::SSLeay::X509_get_issuer_name($x509);
  my $issuer_count = Net::SSLeay::X509_NAME_entry_count($issuer_name);
  $rv->{issuer}->{count} = $issuer_count;
  $rv->{issuer}->{oneline} = Net::SSLeay::X509_NAME_oneline($issuer_name);
  $rv->{issuer}->{print_rfc2253} = Net::SSLeay::X509_NAME_print_ex($issuer_name);
  $rv->{issuer}->{print_rfc2253_utf8} = Net::SSLeay::X509_NAME_print_ex($issuer_name, $flag_rfc22536_utf8);
  $rv->{issuer}->{print_rfc2253_utf8_decoded} = Net::SSLeay::X509_NAME_print_ex($issuer_name, $flag_rfc22536_utf8, 1);
  for my $i (0..$issuer_count-1) {
    my $entry = Net::SSLeay::X509_NAME_get_entry($issuer_name, $i);
    my $asn1_string = Net::SSLeay::X509_NAME_ENTRY_get_data($entry);
    my $asn1_object = Net::SSLeay::X509_NAME_ENTRY_get_object($entry);
    my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
    $rv->{issuer}->{entries}->[$i] = {
          oid  => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
          data => Net::SSLeay::P_ASN1_STRING_get($asn1_string),
          data_utf8_decoded => Net::SSLeay::P_ASN1_STRING_get($asn1_string, 1),
          nid  => ($nid>0) ? $nid : undef,
          ln   => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
          sn   => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,
    };
  }

  warn "Info: dumping alternative names\n";
  $rv->{subject}->{altnames} = [ Net::SSLeay::X509_get_subjectAltNames($x509) ];
  #XXX-TODO maybe add a function for dumping issuerAltNames
  #$rv->{issuer}->{altnames} = [ Net::SSLeay::X509_get_issuerAltNames($x509) ];

  warn "Info: dumping hashes/fingerprints\n";
  $rv->{hash}->{subject} = { dec=>Net::SSLeay::X509_subject_name_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_subject_name_hash($x509)) };
  $rv->{hash}->{issuer}  = { dec=>Net::SSLeay::X509_issuer_name_hash($x509),  hex=>sprintf("%X",Net::SSLeay::X509_issuer_name_hash($x509)) };
  $rv->{hash}->{issuer_and_serial} = { dec=>Net::SSLeay::X509_issuer_and_serial_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_issuer_and_serial_hash($x509)) };
  $rv->{fingerprint}->{md5}  = Net::SSLeay::X509_get_fingerprint($x509, "md5");
  $rv->{fingerprint}->{sha1} = Net::SSLeay::X509_get_fingerprint($x509, "sha1");
  my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1");
  $rv->{digest_sha1}->{pubkey} = Net::SSLeay::X509_pubkey_digest($x509, $sha1_digest);
  $rv->{digest_sha1}->{x509} = Net::SSLeay::X509_digest($x509, $sha1_digest);

  warn "Info: dumping expiration\n";
  $rv->{not_before} = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($x509));
  $rv->{not_after}  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($x509));

  warn "Info: dumping serial number\n";
  my $ai = Net::SSLeay::X509_get_serialNumber($x509);
  $rv->{serial} = {
    hex  => Net::SSLeay::P_ASN1_INTEGER_get_hex($ai),
    dec  => Net::SSLeay::P_ASN1_INTEGER_get_dec($ai),
    long => Net::SSLeay::ASN1_INTEGER_get($ai),
  };
  $rv->{version} = Net::SSLeay::X509_get_version($x509);

  warn "Info: dumping extensions\n";
  my $ext_count = Net::SSLeay::X509_get_ext_count($x509);
  $rv->{extensions}->{count} = $ext_count;
  for my $i (0..$ext_count-1) {
    my $ext = Net::SSLeay::X509_get_ext($x509,$i);
    my $asn1_string = Net::SSLeay::X509_EXTENSION_get_data($ext);
    my $asn1_object = Net::SSLeay::X509_EXTENSION_get_object($ext);
    my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
    $rv->{extensions}->{entries}->[$i] = {
        critical => Net::SSLeay::X509_EXTENSION_get_critical($ext),
        oid      => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
        nid      => ($nid>0) ? $nid : undef,
        ln       => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
        sn       => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,
        data     => Net::SSLeay::X509V3_EXT_print($ext),
    };
  }

  warn "Info: dumping CDP\n";
  $rv->{cdp} = [ Net::SSLeay::P_X509_get_crl_distribution_points($x509) ];
  warn "Info: dumping extended key usage\n";
  $rv->{extkeyusage} = {
    oid => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,0) ],
    nid => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,1) ],
    sn  => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,2) ],
    ln  => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,3) ],
  };
  warn "Info: dumping key usage\n";
  $rv->{keyusage} = [ Net::SSLeay::P_X509_get_key_usage($x509) ];
  warn "Info: dumping netscape cert type\n";
  $rv->{ns_cert_type} = [ Net::SSLeay::P_X509_get_netscape_cert_type($x509) ];

  warn "Info: dumping other info\n";
  $rv->{certificate_type} = Net::SSLeay::X509_certificate_type($x509);
  $rv->{signature_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($x509));
  $rv->{pubkey_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_pubkey_alg($x509));
  $rv->{pubkey_size} = Net::SSLeay::EVP_PKEY_size(Net::SSLeay::X509_get_pubkey($x509));
  $rv->{pubkey_bits} = Net::SSLeay::EVP_PKEY_bits(Net::SSLeay::X509_get_pubkey($x509));
  $rv->{pubkey_id} = Net::SSLeay::EVP_PKEY_id(Net::SSLeay::X509_get_pubkey($x509));

  return $rv;
}

sub dump_details {
  my ($data, $comment) = @_;
  print "\n";
  eval { require Data::Dump };
  if (!$@) {
    # Data::Dump creates nicer output
    print "# $comment\n";
    print "# hashref dumped via Data::Dump\n";
    $Data::Dump::TRY_BASE64 = 0 if $Data::Dump::TRY_BASE64;
    print Data::Dump::pp($data);
  }
  else {
    print "# $comment\n";
    print "# hashref dumped via Data::Dumper\n";
    print Dumper($data);
  }
  print "\n";
}

sub print_basic_info {
  my ($data) = @_;
  print "\n";
  print "Subject:   ", $data->{subject}->{print_rfc2253}, "\n";
  print "Issuer:    ", $data->{issuer}->{print_rfc2253}, "\n";
  print "NotBefore: ", $data->{not_before}, "\n";
  print "NotAfter:  ", $data->{not_after}, "\n";
  print "SHA1: ", $data->{fingerprint}->{sha1}, "\n";
  print "MD5:  ", $data->{fingerprint}->{md5}, "\n";
  print "\n";
}

# --- main
show_usage() if $g_showusage || (!$g_host && !$g_pem);

if ($g_pem) {
  for my $f(@$g_pem) {
    die "ERROR: non existing file '$f'" unless -f $f;

    warn "#### Going to load PEM file '$f'\n";
    my $bio = Net::SSLeay::BIO_new_file($f, 'rb') or die "ERROR: BIO_new_file failed";
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio) or die "ERROR: PEM_read_bio_X509 failed";

    my $cert_details = get_cert_details($x509);

    warn "#### Certificate info\n";
    if ($g_dump) {
      dump_details($cert_details, "exported via command: perl examples/x509_cert_details.pl -dump -pem $f > $f\_dump");
    }
    else {
      print_basic_info($cert_details);
    }
    warn "#### DONE\n";
  }
}

if ($g_host) {
  for my $h (@$g_host) {
    my ($host, $port) = split /:/, $h;
    die "ERROR: invalid host '$h'" unless $host && $port =~ /\d+/;

    warn "#### Going to connect to host=$host, port=$port\n";
    my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp') or die "ERROR: cannot create socket";
    my $ctx = Net::SSLeay::CTX_new() or die "ERROR: CTX_new failed";
    Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
    my $ssl = Net::SSLeay::new($ctx) or die "ERROR: new failed";
    Net::SSLeay::set_fd($ssl, fileno($sock)) or die "ERROR: set_fd failed";
    Net::SSLeay::connect($ssl) or die "ERROR: connect failed";
    my $x509 = Net::SSLeay::get_peer_certificate($ssl);

    my $cert_details = get_cert_details($x509);

    warn "#### Certificate info\n";
    if ($g_dump) {
      dump_details($cert_details, "host: $h\n");
    }
    else {
      print_basic_info($cert_details);
    }
    warn "#### DONE\n";
  }
}
