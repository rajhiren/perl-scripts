#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Term::ANSIColor qw (:constants);

#-- get ciphers in current system
my $system_ciphers =  `openssl ciphers  'ALL:!LOW:!SSLv2:!EXP:!aNULL'`;
chomp($system_ciphers);
my @our_ciphers = split(':',$system_ciphers);

#-- get BitSight recommended ciphers list
my $bitsight_ciphers = `openssl ciphers  'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA'`;
chomp($bitsight_ciphers);
my @bitsight_ciphers = split(':',$bitsight_ciphers);
my %bitsight_ciphers_hash = map { $_ => 1 } @bitsight_ciphers;

#-- get dovecot recommnded ciphers list
my $dovecot_ciphers = `openssl ciphers  'ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW\@STRENGTH'`;
chomp($dovecot_ciphers);
my @dovecot_ciphers = split(':',$dovecot_ciphers);
my %dovecot_ciphers_hash = map { $_ => 1 } @dovecot_ciphers;


my %cipher_recommendation;
foreach my $cipher (@our_ciphers) {
  $cipher_recommendation{"$cipher"}{is_bitsight_approved} =  exists $bitsight_ciphers_hash{"$cipher"} ? 'Y' : 'N';
  $cipher_recommendation{"$cipher"}{is_dovecot_approved} = exists $dovecot_ciphers_hash{"$cipher"} ? 'Y' : 'N';
  $cipher_recommendation{"$cipher"}{is_ISE_approved} =   ( $cipher_recommendation{"$cipher"}{is_bitsight_approved} eq 'Y' and $cipher_recommendation{"$cipher"}{is_dovecot_approved} eq 'Y') ? 'Keep' : 'Drop';
}

foreach my $cipher (sort keys %cipher_recommendation) {
  print BOLD YELLOW, "$cipher,", RESET;
  foreach my $keys (sort keys %{$cipher_recommendation{$cipher}}) {
    my $color;
    if ($cipher_recommendation{$cipher}{$keys} eq "Drop" || $cipher_recommendation{$cipher}{$keys} eq "N") {
      $color = RED;
    } elsif ($cipher_recommendation{$cipher}{$keys} eq "Keep" || $cipher_recommendation{$cipher}{$keys} eq "Y"){
      $color = GREEN;
    } else {
      $color = BLUE;
    }
    # print BOLD $color, "\t$cipher_recommendation{$cipher}{$keys},", RESET;
    print BOLD $color, "\t$cipher_recommendation{$cipher}{$keys},", RESET;

  }
  print "\n";
}
