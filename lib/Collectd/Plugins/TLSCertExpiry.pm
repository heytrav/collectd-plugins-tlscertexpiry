use strict;
use warnings;
package Collectd::Plugins::TLSCertExpiry;

use strict;
use warnings;
use Collectd qw(:all);
use Crypt::OpenSSL::X509;
use DateTime;
use DateTime::Format::Strptime;
use List::Util qw/max/;

our $VERSION = '1.000'; # VERSION
our $certificate_files = [];
our $project;


sub fetch_ssl_expiration {
    my ($cert_path) = @_;
    my $x509 = Crypt::OpenSSL::X509->new_from_file($cert_path);
    my $notAfterDate = $x509->notAfter();
    my $parser = DateTime::Format::Strptime->new(
        pattern => '%b %d %T %Y %Z',
        locale => 'en_NZ'
    );
    return $parser->parse_datetime($notAfterDate);
}

sub days_till_expiry {
    my ($cert_path) = @_;
    
    my $expire_date = fetch_ssl_expiration($cert_path);
    my $now = DateTime->now();
    my $difference_in_days = int(($expire_date->epoch - $now->epoch) / 86400); # seconds in a day
    return max(0, $difference_in_days);
}



sub tls_cert_files_expiry_config {
    my ($config) = @_;
    foreach my $item (@{$config->{'children'}}) {
        my $key = lc($item->{'key'});
        if ($key eq 'certificates') {
          $certificate_files = $item->{'values'}
        }
        elsif ($key eq 'project') {
          $project = $key;
        }
    }
    
   return 1; 
}

sub tls_cert_files_expiry_read {

    foreach my $cert_file (@{$certificate_files}) {
        (my $cert_file_name = $cert_file) =~ s!.+?/?([^/]+)$!$1!;
        my $days_left = days_till_expiry($cert_file);
        plugin_log(LOG_WARNING, "cert file: $cert_file_name expires in $days_left days") if $days_left < 50;

        my $value_list = {
            plugin => 'tls_cert_files_expiry',
            plugin_instance => $cert_file_name,
            type => 'gauge',
            type_instance => $project
            interval => plugin_get_interval(),
            values => [$days_left]
        };
        plugin_dispatch_values($value_list);
    }
    
    return 1;
}



plugin_register(TYPE_CONFIG, "TLSCertExpiry", "tls_cert_files_expiry_config");
plugin_register(TYPE_READ, "TLSCertExpiry", "tls_cert_files_expiry_read");
1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Collectd::Plugins::RedisClient - collectd plugin for reading counters from a redis server

=head1 VERSION

version 1.001

=head1 SYNOPSIS

This is a collectd plugin for reading expiration date from a list of TLS certificate files

In your collectd config:


    <LoadPlugin "perl">
        Globals true
    </LoadPlugin>
    
    <Plugin "perl">
    BaseName "Collectd::Plugins"
    LoadPlugin "TLSCertExpiry"
    
        <Plugin "TLSCertExpiry">
            certificates "/path/to/my-cert.pem" "/path/to/another-cert.pem" "/path/to/yet-another-cert.cert"
        </Plugin>
    </Plugin>
