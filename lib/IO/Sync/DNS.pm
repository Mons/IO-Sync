package IO::Sync::DNS;

use strict;
use Net::ADNS ();
use Errno ();
use Carp;
#use uni::perl ':dumper';

sub resolve {
	my ($type,$host,$timeout) = @_;
	$timeout ||= 2;
	my $adns = Net::ADNS->new();
	warn "submit host = $host, type = $type";
	$adns->submit( $host, $type );
	my ($r, $w, $e, $t) = $adns->before_select;
	if( select($r, $w, $e, $timeout) ) {
		if (my $answer = $adns->check) {
			warn "Got answer for $host ";# . dumper $answer;
			return $answer;
		}
	} else {
		warn "select failed: $!";
	}
	$! = Errno::ETIMEDOUT;
	return;
}

sub a($;$) {
	my ($host,$timeout) = @_;
	my $res = resolve( Net::ADNS::ADNS_R_A, $host, $timeout );
	return @{ $res->{records} } if $res && $res->{records};
	return;
}

sub aaaa($;$) {
	my ($host,$timeout) = @_;
	croak "No ipv6 yet";
}

sub srv($$$;$) {
	my ($service,$proto,$domain,$timeout) = @_;
	my $res = resolve( Net::ADNS::ADNS_R_SRV_RAW,  "_$service._$proto.$domain", $timeout );
	return map { [ split /\s+/, $_, 4 ] } @{ $res->{records} } if $res && $res->{records};
	return;
}

# TODO: all others

1;
